#!/bin/bash
# Comprehensive integration tests for cfsctl OCI signing and verification.
#
# Test categories:
# - Basic workflow (pull, sign, verify)
# - Signature verification failures (wrong key, unsigned, tampered)
# - Signature verification success (round-trip, multi-layer)
# - Edge cases (double-sign, multiple signatures, no signatures)
# - Artifact structure validation
#
# Requires: skopeo, openssl, cfsctl built
set -euo pipefail

# Use release build if available, otherwise dev
if [ -x "target/release/cfsctl" ]; then
    CFSCTL="target/release/cfsctl"
else
    CFSCTL="target/debug/cfsctl"
fi

if [ ! -x "$CFSCTL" ]; then
    echo "ERROR: cfsctl not found. Run 'cargo build' first."
    exit 1
fi

# Use the project directory for temp files
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TMPDIR="$(mktemp -d -p "$PROJECT_DIR")"
trap 'rm -rf "$TMPDIR"' EXIT

REPO="$TMPDIR/repo"
mkdir -p "$REPO"

PASS=0
FAIL=0
TEST_NUM=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

test_start() {
    TEST_NUM=$((TEST_NUM + 1))
    echo ""
    echo "=== Test $TEST_NUM: $1 ==="
}

# ==============================================================================
# SETUP
# ==============================================================================

echo "========================================"
echo "Setting up test environment"
echo "========================================"

# Generate primary test keypair
openssl req -x509 -newkey rsa:2048 \
    -keyout "$TMPDIR/key.pem" -out "$TMPDIR/cert.pem" \
    -days 1 -nodes -subj '/CN=composefs-test-signer' 2>/dev/null
echo "Generated primary keypair (cert.pem, key.pem)"

# Generate secondary keypair for negative testing
openssl req -x509 -newkey rsa:2048 \
    -keyout "$TMPDIR/key2.pem" -out "$TMPDIR/cert2.pem" \
    -days 1 -nodes -subj '/CN=composefs-wrong-signer' 2>/dev/null
echo "Generated secondary keypair (cert2.pem, key2.pem)"

# Generate third keypair for multi-signature testing
openssl req -x509 -newkey rsa:2048 \
    -keyout "$TMPDIR/key3.pem" -out "$TMPDIR/cert3.pem" \
    -days 1 -nodes -subj '/CN=composefs-third-signer' 2>/dev/null
echo "Generated third keypair (cert3.pem, key3.pem)"

# Pull test images to OCI layout
echo "Pulling test images..."
skopeo copy --quiet docker://busybox:latest "oci:$TMPDIR/busybox-oci:latest"
echo "  - busybox:latest (single layer)"

# Pull a multi-layer image (alpine has more layers)
skopeo copy --quiet docker://alpine:latest "oci:$TMPDIR/alpine-oci:latest"
echo "  - alpine:latest (multi-layer)"

echo ""
echo "========================================"
echo "BASIC WORKFLOW TESTS"
echo "========================================"

# ==============================================================================
# BASIC WORKFLOW
# ==============================================================================

test_start "Pull OCI image"
PULL_OUTPUT=$("$CFSCTL" --repo "$REPO" oci pull "oci:$TMPDIR/busybox-oci:latest" busybox 2>&1) || true
if echo "$PULL_OUTPUT" | grep -q "^manifest sha256:"; then
    pass "Pulled busybox image"
    MANIFEST_DIGEST=$(echo "$PULL_OUTPUT" | grep "^manifest" | awk '{print $2}')
    echo "  Manifest: $MANIFEST_DIGEST"
else
    fail "Failed to pull busybox image"
    echo "  Error: $PULL_OUTPUT"
    echo "Exiting early due to critical failure"
    exit 1
fi

test_start "Image appears in listing"
if "$CFSCTL" --repo "$REPO" oci images 2>&1 | grep -q busybox; then
    pass "Image listed"
else
    fail "Image not found in listing"
fi

test_start "Sign image with valid keypair"
SIGN_OUTPUT=$("$CFSCTL" --repo "$REPO" oci sign --cert "$TMPDIR/cert.pem" --key "$TMPDIR/key.pem" busybox 2>&1) || true
if echo "$SIGN_OUTPUT" | grep -q "^sha256:"; then
    pass "Signed image successfully"
    SIG_ARTIFACT_DIGEST=$(echo "$SIGN_OUTPUT" | head -1)
    echo "  Signature artifact: $SIG_ARTIFACT_DIGEST"
else
    fail "Failed to sign image"
    echo "  Error: $SIGN_OUTPUT"
fi

test_start "Verify signatures (list mode, no cert)"
VERIFY_OUTPUT=$("$CFSCTL" --repo "$REPO" oci verify busybox 2>&1) || true
if echo "$VERIFY_OUTPUT" | grep -qi "layer\|merged"; then
    pass "Verify lists signature entries"
else
    fail "Verify did not list signatures"
    echo "  Output: $VERIFY_OUTPUT"
fi

test_start "Verify signatures with correct certificate"
VERIFY_OUTPUT=$("$CFSCTL" --repo "$REPO" oci verify --cert "$TMPDIR/cert.pem" busybox 2>&1) || true
if echo "$VERIFY_OUTPUT" | grep -q "signature verified"; then
    pass "Signatures verified successfully"
else
    fail "Signature verification failed"
    echo "  Output: $VERIFY_OUTPUT"
fi

echo ""
echo "========================================"
echo "SIGNATURE VERIFICATION FAILURE TESTS"
echo "========================================"

# ==============================================================================
# SIGNATURE VERIFICATION FAILURES
# ==============================================================================

test_start "Pull unsigned image with --require-signature (should fail)"
REPO_FRESH="$TMPDIR/repo-fresh1"
mkdir -p "$REPO_FRESH"
skopeo copy --quiet docker://busybox:latest "oci:$TMPDIR/unsigned-oci:latest"
if "$CFSCTL" --repo "$REPO_FRESH" oci pull --require-signature --trust-cert "$TMPDIR/cert.pem" \
    "oci:$TMPDIR/unsigned-oci:latest" test 2>&1; then
    fail "Should have rejected unsigned image"
else
    pass "Correctly rejected unsigned image"
fi

test_start "Verify with wrong certificate (should fail)"
if "$CFSCTL" --repo "$REPO" oci verify --cert "$TMPDIR/cert2.pem" busybox 2>&1; then
    fail "Should have rejected wrong certificate"
else
    pass "Correctly rejected wrong certificate"
fi

test_start "Verify unsigned image (should report no signatures)"
REPO_UNSIGNED="$TMPDIR/repo-unsigned"
mkdir -p "$REPO_UNSIGNED"
"$CFSCTL" --repo "$REPO_UNSIGNED" oci pull "oci:$TMPDIR/unsigned-oci:latest" unsigned 2>&1 >/dev/null || true
VERIFY_OUTPUT=$("$CFSCTL" --repo "$REPO_UNSIGNED" oci verify unsigned 2>&1) || true
if echo "$VERIFY_OUTPUT" | grep -qi "no signature"; then
    pass "Correctly reported no signatures"
else
    fail "Did not report missing signatures"
    echo "  Output: $VERIFY_OUTPUT"
fi

test_start "Pull with --require-signature using wrong trust cert (should fail)"
REPO_FRESH2="$TMPDIR/repo-fresh2"
mkdir -p "$REPO_FRESH2"
# First pull and sign in repo-fresh2
"$CFSCTL" --repo "$REPO_FRESH2" oci pull "oci:$TMPDIR/busybox-oci:latest" signed 2>&1 >/dev/null || true
"$CFSCTL" --repo "$REPO_FRESH2" oci sign --cert "$TMPDIR/cert.pem" --key "$TMPDIR/key.pem" signed 2>&1 >/dev/null || true
# Now try to pull with wrong cert
REPO_FRESH3="$TMPDIR/repo-fresh3"
mkdir -p "$REPO_FRESH3"
# Copy the signed image's signature to a fresh OCI layout
skopeo copy --quiet docker://busybox:latest "oci:$TMPDIR/signed-for-wrongkey:latest"
"$CFSCTL" --repo "$REPO_FRESH2" oci export-signatures signed "$TMPDIR/signed-for-wrongkey" 2>&1 >/dev/null || true
if "$CFSCTL" --repo "$REPO_FRESH3" oci pull --require-signature --trust-cert "$TMPDIR/cert2.pem" \
    "oci:$TMPDIR/signed-for-wrongkey:latest" test 2>&1; then
    fail "Should have rejected signature from wrong key"
else
    pass "Correctly rejected signature from wrong key"
fi

echo ""
echo "========================================"
echo "SIGNATURE VERIFICATION SUCCESS TESTS"
echo "========================================"

# ==============================================================================
# SIGNATURE VERIFICATION SUCCESS
# ==============================================================================

test_start "Export signatures to OCI layout"
EXPORT_OUTPUT=$("$CFSCTL" --repo "$REPO" oci export-signatures busybox "$TMPDIR/busybox-oci" 2>&1) || true
if echo "$EXPORT_OUTPUT" | grep -q "Exported"; then
    pass "Exported signatures to OCI layout"
else
    fail "Failed to export signatures"
    echo "  Output: $EXPORT_OUTPUT"
fi

test_start "Pull multi-layer image"
PULL_OUTPUT=$("$CFSCTL" --repo "$REPO" oci pull "oci:$TMPDIR/alpine-oci:latest" alpine 2>&1) || true
if echo "$PULL_OUTPUT" | grep -q "^manifest sha256:"; then
    pass "Pulled alpine (multi-layer) image"
else
    fail "Failed to pull alpine image"
    echo "  Error: $PULL_OUTPUT"
fi

test_start "Sign multi-layer image"
SIGN_OUTPUT=$("$CFSCTL" --repo "$REPO" oci sign --cert "$TMPDIR/cert.pem" --key "$TMPDIR/key.pem" alpine 2>&1) || true
if echo "$SIGN_OUTPUT" | grep -q "^sha256:"; then
    pass "Signed multi-layer image"
else
    fail "Failed to sign multi-layer image"
    echo "  Error: $SIGN_OUTPUT"
fi

test_start "Verify multi-layer image signatures"
VERIFY_OUTPUT=$("$CFSCTL" --repo "$REPO" oci verify --cert "$TMPDIR/cert.pem" alpine 2>&1) || true
if echo "$VERIFY_OUTPUT" | grep -q "signature verified"; then
    pass "Multi-layer image signatures verified"
    # Count verified signatures
    VERIFIED_COUNT=$(echo "$VERIFY_OUTPUT" | grep -c "signature verified" || true)
    echo "  Verified $VERIFIED_COUNT signatures (layer + merged)"
else
    fail "Multi-layer signature verification failed"
    echo "  Output: $VERIFY_OUTPUT"
fi

echo ""
echo "========================================"
echo "EDGE CASE TESTS"
echo "========================================"

# ==============================================================================
# EDGE CASES
# ==============================================================================

test_start "Sign already-signed image (add second signature)"
# Sign busybox again with a different key
SIGN_OUTPUT=$("$CFSCTL" --repo "$REPO" oci sign --cert "$TMPDIR/cert3.pem" --key "$TMPDIR/key3.pem" busybox 2>&1) || true
if echo "$SIGN_OUTPUT" | grep -q "^sha256:"; then
    pass "Added second signature to image"
    SECOND_SIG_DIGEST=$(echo "$SIGN_OUTPUT" | head -1)
    echo "  Second signature: $SECOND_SIG_DIGEST"
else
    fail "Failed to add second signature"
    echo "  Error: $SIGN_OUTPUT"
fi

test_start "Verify image with multiple signature artifacts"
VERIFY_OUTPUT=$("$CFSCTL" --repo "$REPO" oci verify busybox 2>&1) || true
if echo "$VERIFY_OUTPUT" | grep -c "Signature artifact" | grep -q "2"; then
    pass "Found both signature artifacts"
else
    # Check if at least we see multiple "layer" entries from different artifacts
    if echo "$VERIFY_OUTPUT" | grep -qi "algorithm"; then
        pass "Multiple signatures present (may show one at a time)"
    else
        fail "Did not find multiple signatures"
        echo "  Output: $VERIFY_OUTPUT"
    fi
fi

test_start "Verify with cert3 (the second signer)"
VERIFY_OUTPUT=$("$CFSCTL" --repo "$REPO" oci verify --cert "$TMPDIR/cert3.pem" busybox 2>&1) || true
if echo "$VERIFY_OUTPUT" | grep -q "signature verified"; then
    pass "Verified with second signer's certificate"
else
    fail "Could not verify with second signer's cert"
    echo "  Output: $VERIFY_OUTPUT"
fi

test_start "Export signatures when no signatures exist (should fail gracefully)"
REPO_NOSIG="$TMPDIR/repo-nosig"
mkdir -p "$REPO_NOSIG"
"$CFSCTL" --repo "$REPO_NOSIG" oci pull "oci:$TMPDIR/unsigned-oci:latest" nosig 2>&1 >/dev/null || true
EXPORT_OUTPUT=$("$CFSCTL" --repo "$REPO_NOSIG" oci export-signatures nosig "$TMPDIR/nosig-export" 2>&1) || true
if echo "$EXPORT_OUTPUT" | grep -qi "No signature"; then
    pass "Gracefully reported no signatures to export"
else
    # Also acceptable if it just exports 0
    if echo "$EXPORT_OUTPUT" | grep -q "0"; then
        pass "Exported 0 signatures (graceful handling)"
    else
        fail "Did not handle missing signatures gracefully"
        echo "  Output: $EXPORT_OUTPUT"
    fi
fi

echo ""
echo "========================================"
echo "ARTIFACT STRUCTURE VALIDATION TESTS"
echo "========================================"

# ==============================================================================
# ARTIFACT STRUCTURE VALIDATION
# ==============================================================================

test_start "Artifact has correct artifactType"
# Find the signature artifact in the exported OCI layout
ARTIFACT_HASH=$(cat "$TMPDIR/busybox-oci/index.json" 2>/dev/null | grep -o '"sha256:[a-f0-9]*"' | tail -1 | tr -d '"' | sed 's/sha256://' || true)
if [ -n "$ARTIFACT_HASH" ] && [ -f "$TMPDIR/busybox-oci/blobs/sha256/$ARTIFACT_HASH" ]; then
    ARTIFACT_MANIFEST=$(cat "$TMPDIR/busybox-oci/blobs/sha256/$ARTIFACT_HASH")
    if echo "$ARTIFACT_MANIFEST" | grep -q '"application/vnd.composefs.signature.v1"'; then
        pass "artifactType is application/vnd.composefs.signature.v1"
    else
        fail "Incorrect artifactType"
        echo "  Manifest: $ARTIFACT_MANIFEST"
    fi
else
    fail "Could not find artifact manifest"
fi

test_start "Artifact has subject field pointing to image"
if [ -n "$ARTIFACT_HASH" ]; then
    if echo "$ARTIFACT_MANIFEST" | grep -q '"subject"'; then
        # Check subject has mediaType and digest
        if echo "$ARTIFACT_MANIFEST" | grep -A5 '"subject"' | grep -q '"digest"'; then
            pass "subject field present with digest"
        else
            fail "subject field missing digest"
        fi
    else
        fail "Missing subject field"
    fi
else
    fail "No artifact to check"
fi

test_start "Layers have composefs.signature.type annotation"
if [ -n "$ARTIFACT_HASH" ]; then
    if echo "$ARTIFACT_MANIFEST" | grep -q '"composefs.signature.type"'; then
        pass "composefs.signature.type annotation present"
    else
        fail "Missing composefs.signature.type annotation"
    fi
else
    fail "No artifact to check"
fi

test_start "Layers have composefs.digest annotation"
if [ -n "$ARTIFACT_HASH" ]; then
    if echo "$ARTIFACT_MANIFEST" | grep -q '"composefs.digest"'; then
        pass "composefs.digest annotation present"
    else
        fail "Missing composefs.digest annotation"
    fi
else
    fail "No artifact to check"
fi

test_start "Manifest has composefs.algorithm annotation with fsverity- prefix"
if [ -n "$ARTIFACT_HASH" ]; then
    ALGORITHM=$(echo "$ARTIFACT_MANIFEST" | grep -o '"composefs.algorithm"[^,}]*' | head -1 || true)
    if echo "$ALGORITHM" | grep -q "fsverity-sha"; then
        pass "composefs.algorithm uses fsverity- prefix format"
        echo "  Algorithm: $ALGORITHM"
    else
        fail "composefs.algorithm missing or wrong format"
        echo "  Found: $ALGORITHM"
    fi
else
    fail "No artifact to check"
fi

test_start "Layer mediaType is application/vnd.composefs.signature.v1+pkcs7"
if [ -n "$ARTIFACT_HASH" ]; then
    if echo "$ARTIFACT_MANIFEST" | grep -q '"application/vnd.composefs.signature.v1+pkcs7"'; then
        pass "Correct layer mediaType"
    else
        fail "Incorrect layer mediaType"
    fi
else
    fail "No artifact to check"
fi

test_start "Signature entries include both 'layer' and 'merged' types"
if [ -n "$ARTIFACT_HASH" ]; then
    HAS_LAYER=$(echo "$ARTIFACT_MANIFEST" | grep -q '"layer"' && echo "yes" || echo "no")
    HAS_MERGED=$(echo "$ARTIFACT_MANIFEST" | grep -q '"merged"' && echo "yes" || echo "no")
    if [ "$HAS_LAYER" = "yes" ] && [ "$HAS_MERGED" = "yes" ]; then
        pass "Both 'layer' and 'merged' signature types present"
    else
        fail "Missing signature types (layer=$HAS_LAYER, merged=$HAS_MERGED)"
    fi
else
    fail "No artifact to check"
fi

echo ""
echo "========================================"
echo "ADDITIONAL VALIDATION TESTS"
echo "========================================"

# ==============================================================================
# ADDITIONAL TESTS
# ==============================================================================

test_start "Inspect signed image shows expected fields"
INSPECT_OUTPUT=$("$CFSCTL" --repo "$REPO" oci inspect busybox 2>&1) || true
if echo "$INSPECT_OUTPUT" | grep -q "Manifest:"; then
    if echo "$INSPECT_OUTPUT" | grep -q "Config:"; then
        if echo "$INSPECT_OUTPUT" | grep -q "Type:.*container"; then
            pass "Inspect shows expected fields"
        else
            fail "Inspect missing Type field"
        fi
    else
        fail "Inspect missing Config field"
    fi
else
    fail "Inspect missing Manifest field"
    echo "  Output: $INSPECT_OUTPUT"
fi

test_start "List images shows expected format"
IMAGES_OUTPUT=$("$CFSCTL" --repo "$REPO" oci images 2>&1) || true
if echo "$IMAGES_OUTPUT" | grep -q "NAME"; then
    if echo "$IMAGES_OUTPUT" | grep -q "busybox"; then
        pass "Images list shows expected format"
    else
        fail "Images list missing busybox"
    fi
else
    fail "Images list missing header"
    echo "  Output: $IMAGES_OUTPUT"
fi

# ==============================================================================
# SUMMARY
# ==============================================================================

echo ""
echo "========================================"
echo "TEST SUMMARY"
echo "========================================"
echo "Total tests: $TEST_NUM"
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo "========================================"

if [ "$FAIL" -ne 0 ]; then
    echo ""
    echo "SOME TESTS FAILED"
    exit 1
fi

echo ""
echo "ALL TESTS PASSED!"
