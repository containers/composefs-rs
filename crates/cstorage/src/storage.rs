commit 6df850d9da4ab27fdfab0670f083211832d4c2c9
Author:     Colin Walters <walters@verbum.org>
AuthorDate: Tue Apr 7 11:57:59 2026 -0400
Commit:     Colin Walters <walters@verbum.org>
CommitDate: Tue Apr 7 11:59:42 2026 -0400

    oci: Add containers-storage integration with zero-copy import
    
    Add support for importing OCI images directly from containers-storage
    (Podman/Buildah/CRI-O) into composefs repositories, using zero-copy
    operations (reflinks or hardlinks) when possible.
    
    Assisted-by: OpenCode (Claude Opus 4)
    Signed-off-by: Colin Walters <walters@verbum.org>

diff --git a/crates/cstorage/src/storage.rs b/crates/cstorage/src/storage.rs
index 4ebd319a..b43bae54 100644
--- a/crates/cstorage/src/storage.rs
+++ b/crates/cstorage/src/storage.rs
@@ -163,6 +163,16 @@ impl Storage {
             Err(_) => return Vec::new(),
         };
 
+        Self::parse_additional_image_stores(&opts)
+    }
+
+    /// Parse a `STORAGE_OPTS` value for `additionalimagestore=<path>` entries
+    /// and open any that point to valid overlay storage.
+    ///
+    /// This is separated from [`additional_image_stores_from_env()`] so the
+    /// parsing logic can be tested without mutating process-global environment
+    /// variables.
+    fn parse_additional_image_stores(opts: &str) -> Vec<Self> {
         let mut stores = Vec::new();
         // STORAGE_OPTS is comma-separated, e.g.
         // "additionalimagestore=/run/host-container-storage,additionalimagestore=/other"
@@ -725,49 +735,39 @@ mod tests {
     }
 
     #[test]
-    fn test_additional_image_stores_from_env() {
+    fn test_parse_additional_image_stores() {
         let dir = tempfile::tempdir().unwrap();
         let store_a = dir.path().join("a");
         let store_b = dir.path().join("b");
         create_mock_storage(&store_a);
         create_mock_storage(&store_b);
 
-        // With no env var, returns empty
-        env::remove_var("STORAGE_OPTS");
-        assert!(Storage::additional_image_stores_from_env().is_empty());
+        // Empty string returns empty
+        assert!(Storage::parse_additional_image_stores("").is_empty());
 
         // Single store
-        env::set_var(
-            "STORAGE_OPTS",
-            format!("additionalimagestore={}", store_a.display()),
-        );
-        let stores = Storage::additional_image_stores_from_env();
+        let opts = format!("additionalimagestore={}", store_a.display());
+        let stores = Storage::parse_additional_image_stores(&opts);
         assert_eq!(stores.len(), 1);
 
         // Multiple stores (comma-separated)
-        env::set_var(
-            "STORAGE_OPTS",
-            format!(
-                "additionalimagestore={},additionalimagestore={}",
-                store_a.display(),
-                store_b.display()
-            ),
+        let opts = format!(
+            "additionalimagestore={},additionalimagestore={}",
+            store_a.display(),
+            store_b.display()
         );
-        let stores = Storage::additional_image_stores_from_env();
+        let stores = Storage::parse_additional_image_stores(&opts);
         assert_eq!(stores.len(), 2);
 
         // Non-existent path is silently skipped
-        env::set_var("STORAGE_OPTS", "additionalimagestore=/no/such/path");
-        assert!(Storage::additional_image_stores_from_env().is_empty());
+        assert!(
+            Storage::parse_additional_image_stores("additionalimagestore=/no/such/path").is_empty()
+        );
 
         // Unrelated options are ignored
-        env::set_var(
-            "STORAGE_OPTS",
-            "overlay.mount_program=/usr/bin/fuse-overlayfs",
+        assert!(
+            Storage::parse_additional_image_stores("overlay.mount_program=/usr/bin/fuse-overlayfs")
+                .is_empty()
         );
-        assert!(Storage::additional_image_stores_from_env().is_empty());
-
-        // Clean up
-        env::remove_var("STORAGE_OPTS");
     }
 }
