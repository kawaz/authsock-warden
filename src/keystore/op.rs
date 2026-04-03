//! 1Password CLI (op) integration for SSH key management
//!
//! Provides lazy-loaded access to SSH keys stored in 1Password vaults.
//! Keys are discovered via `op item list` and retrieved on-demand via `op item get`.
//!
//! Design rationale: All op CLI calls happen lazily (not at startup) because each
//! call may require TouchID authentication. The first REQUEST_IDENTITIES or
//! SIGN_REQUEST triggers the initial discovery.

use crate::error::{Error, Result};
use serde::Deserialize;
use std::process::Command;
use std::sync::OnceLock;
use tracing::{debug, info};
use zeroize::{Zeroize, Zeroizing};

/// Global account setting for op CLI (thread-safe, set once at startup)
static OP_ACCOUNT: OnceLock<String> = OnceLock::new();

/// Set the 1Password account for all op CLI calls.
/// Should be called once at startup from config.
pub fn set_account(account: String) {
    let _ = OP_ACCOUNT.set(account);
}

/// Create an `op` command with account selection if configured.
fn op_command() -> Command {
    let mut cmd = Command::new("op");
    if let Some(account) = OP_ACCOUNT.get() {
        cmd.args(["--account", account]);
    }
    cmd
}

/// An SSH key item discovered from 1Password
#[derive(Debug, Clone)]
pub struct OpKeyInfo {
    /// 1Password item ID (used for retrieval)
    pub item_id: String,
    /// Human-readable title
    pub title: String,
    /// Vault ID
    pub vault_id: String,
    /// Vault name
    pub vault_name: String,
    /// Key fingerprint (e.g., "SHA256:aKmTBeL9...")
    pub fingerprint: String,
}

/// JSON structure from `op item list`
#[derive(Debug, Deserialize)]
struct OpItemListEntry {
    id: String,
    title: String,
    vault: OpVault,
    additional_information: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpVault {
    id: String,
    name: String,
}

/// JSON structure from `op item get --fields`
#[derive(Debug, Deserialize)]
struct OpFieldValue {
    value: String,
}

/// List SSH key items from 1Password.
///
/// Optionally filtered by vault name/id and item title/id.
/// Each op CLI invocation may trigger TouchID.
pub fn list_ssh_keys(
    vault_filter: Option<&str>,
    item_filter: Option<&str>,
) -> Result<Vec<OpKeyInfo>> {
    let mut cmd = op_command();
    cmd.args([
        "item",
        "list",
        "--categories",
        "SSH Key",
        "--format",
        "json",
    ]);

    // vault filter via CLI arg (more efficient than post-filtering)
    if let Some(vault) = vault_filter {
        cmd.args(["--vault", vault]);
    }

    debug!("Running: op item list --categories SSH Key");
    let output = cmd.output().map_err(|e| {
        Error::KeyStore(format!(
            "Failed to execute op CLI: {}. Is 1Password CLI installed?",
            e
        ))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::KeyStore(format!(
            "op item list failed: {}",
            stderr.trim()
        )));
    }

    let entries: Vec<OpItemListEntry> = serde_json::from_slice(&output.stdout)
        .map_err(|e| Error::KeyStore(format!("Failed to parse op item list output: {}", e)))?;

    let mut keys = parse_item_list(entries);

    // Apply item filter (title or id match)
    if let Some(item) = item_filter {
        keys.retain(|k| k.title == item || k.item_id == item);
    }

    info!(count = keys.len(), "Discovered SSH keys from 1Password");
    Ok(keys)
}

/// Parse op item list JSON entries into OpKeyInfo, filtering to valid SSH keys.
fn parse_item_list(entries: Vec<OpItemListEntry>) -> Vec<OpKeyInfo> {
    entries
        .into_iter()
        .filter_map(|entry| {
            let fingerprint = entry.additional_information?;
            if !fingerprint.starts_with("SHA256:") {
                return None;
            }
            Some(OpKeyInfo {
                item_id: entry.id,
                title: entry.title,
                vault_id: entry.vault.id,
                vault_name: entry.vault.name,
                fingerprint,
            })
        })
        .collect()
}

/// Validate that an item ID is safe to pass to the op CLI.
///
/// 1Password item IDs are 26-character alphanumeric strings.
/// This prevents injection of CLI flags (e.g., item_id starting with "--").
fn validate_item_id(item_id: &str) -> Result<()> {
    if !item_id.is_empty() && item_id.chars().all(|c| c.is_ascii_alphanumeric()) {
        Ok(())
    } else {
        Err(Error::KeyStore(format!("Invalid item ID: {}", item_id)))
    }
}

/// Get the public key for an item.
///
/// Returns the public key in OpenSSH format (e.g., "ssh-ed25519 AAAA...").
pub fn get_public_key(item_id: &str) -> Result<String> {
    validate_item_id(item_id)?;
    debug!(item_id, "Fetching public key from 1Password");
    let output = op_command()
        .args([
            "item",
            "get",
            item_id,
            "--fields",
            "public_key",
            "--format",
            "json",
        ])
        .output()
        .map_err(|e| Error::KeyStore(format!("Failed to execute op: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::KeyStore(format!(
            "op item get (public key) failed: {}",
            stderr.trim()
        )));
    }

    let field: OpFieldValue = serde_json::from_slice(&output.stdout)
        .map_err(|e| Error::KeyStore(format!("Failed to parse public key field: {}", e)))?;

    Ok(field.value)
}

/// Get the private key PEM for an item.
///
/// Returns the private key in PEM format (typically PKCS#8 "BEGIN PRIVATE KEY").
/// The returned value is wrapped in `Zeroizing` to ensure the PEM string is
/// securely erased from memory when dropped.
pub fn get_private_key(item_id: &str) -> Result<Zeroizing<String>> {
    validate_item_id(item_id)?;
    debug!(item_id, "Fetching private key from 1Password");
    let mut output = op_command()
        .args([
            "item",
            "get",
            item_id,
            "--fields",
            "private_key",
            "--reveal",
            "--format",
            "json",
        ])
        .output()
        .map_err(|e| Error::KeyStore(format!("Failed to execute op: {}", e)))?;

    if !output.status.success() {
        // Zeroize stdout even on failure — it may contain partial secret data
        output.stdout.zeroize();
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::KeyStore(format!(
            "op item get (private key) failed: {}",
            stderr.trim()
        )));
    }

    let field: OpFieldValue = serde_json::from_slice(&output.stdout).map_err(|e| {
        output.stdout.zeroize();
        Error::KeyStore(format!("Failed to parse private key field: {}", e))
    })?;

    // Zeroize the raw stdout buffer now that the PEM value has been extracted
    output.stdout.zeroize();

    Ok(Zeroizing::new(field.value))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- JSON parsing tests (no op CLI needed) ---

    #[test]
    fn parse_item_list_single_key() {
        let json = r#"[
            {
                "id": "zl4nsgmrs73isw6mlc464tpecy",
                "title": "SSH: kawaz@kawaz-mbp.local_20151013",
                "vault": { "id": "2pzwth2z4d2ni7jvstuuwnsfle", "name": "Private" },
                "category": "SSH_KEY",
                "additional_information": "SHA256:aKmTBeL9vdtjrDYIq65Fv3GMc3UeVYEq+cFDs//Hwoo"
            }
        ]"#;

        let entries: Vec<OpItemListEntry> = serde_json::from_str(json).unwrap();
        let keys = parse_item_list(entries);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].item_id, "zl4nsgmrs73isw6mlc464tpecy");
        assert_eq!(keys[0].title, "SSH: kawaz@kawaz-mbp.local_20151013");
        assert_eq!(keys[0].vault_name, "Private");
        assert_eq!(
            keys[0].fingerprint,
            "SHA256:aKmTBeL9vdtjrDYIq65Fv3GMc3UeVYEq+cFDs//Hwoo"
        );
    }

    #[test]
    fn parse_item_list_multiple_keys() {
        let json = r#"[
            {
                "id": "id1",
                "title": "Key 1",
                "vault": { "id": "v1", "name": "Work" },
                "category": "SSH_KEY",
                "additional_information": "SHA256:aaaa"
            },
            {
                "id": "id2",
                "title": "Key 2",
                "vault": { "id": "v2", "name": "Personal" },
                "category": "SSH_KEY",
                "additional_information": "SHA256:bbbb"
            }
        ]"#;

        let entries: Vec<OpItemListEntry> = serde_json::from_str(json).unwrap();
        let keys = parse_item_list(entries);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].vault_name, "Work");
        assert_eq!(keys[1].vault_name, "Personal");
    }

    #[test]
    fn parse_item_list_skips_entries_without_fingerprint() {
        let json = r#"[
            {
                "id": "id1",
                "title": "Key without info",
                "vault": { "id": "v1", "name": "Vault" },
                "category": "SSH_KEY",
                "additional_information": null
            },
            {
                "id": "id2",
                "title": "Key with fingerprint",
                "vault": { "id": "v2", "name": "Vault" },
                "category": "SSH_KEY",
                "additional_information": "SHA256:valid"
            }
        ]"#;

        let entries: Vec<OpItemListEntry> = serde_json::from_str(json).unwrap();
        let keys = parse_item_list(entries);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].item_id, "id2");
    }

    #[test]
    fn parse_item_list_skips_non_sha256_fingerprints() {
        let json = r#"[
            {
                "id": "id1",
                "title": "Key with MD5",
                "vault": { "id": "v1", "name": "Vault" },
                "category": "SSH_KEY",
                "additional_information": "MD5:ab:cd:ef"
            }
        ]"#;

        let entries: Vec<OpItemListEntry> = serde_json::from_str(json).unwrap();
        let keys = parse_item_list(entries);
        assert!(keys.is_empty());
    }

    #[test]
    fn parse_item_list_empty() {
        let entries: Vec<OpItemListEntry> = Vec::new();
        let keys = parse_item_list(entries);
        assert!(keys.is_empty());
    }

    #[test]
    fn parse_public_key_field_json() {
        let json = r#"{
            "id": "public_key",
            "type": "STRING",
            "label": "public key",
            "value": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4iVKt+ZpGfomPzaOHpINmRMWDS7lOUD0HXBgTb6UjJ"
        }"#;

        let field: OpFieldValue = serde_json::from_str(json).unwrap();
        assert!(field.value.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn parse_private_key_field_json() {
        let json = r#"{
            "id": "private_key",
            "type": "SSHKEY",
            "value": "-----BEGIN PRIVATE KEY-----\nMFMCAQEwBQYDK2VwBCIEILfg0K3JM0GwuUuqBcJ79jKqV2owfa4zpRsarl64dDjC\noSMDIQBuIlSrfmaRn6Jj82jh6SDZkTFg0u5TlA9B1wYE2+lIyQ==\n-----END PRIVATE KEY-----\n"
        }"#;

        let field: OpFieldValue = serde_json::from_str(json).unwrap();
        assert!(field.value.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn op_field_value_ignores_extra_fields() {
        // op CLI may return additional fields we don't care about
        let json = r#"{
            "id": "public_key",
            "type": "STRING",
            "label": "public key",
            "reference": "op://vault/item/public_key",
            "value": "ssh-ed25519 AAAA..."
        }"#;

        let field: OpFieldValue = serde_json::from_str(json).unwrap();
        assert_eq!(field.value, "ssh-ed25519 AAAA...");
    }

    #[test]
    fn op_item_list_entry_ignores_extra_fields() {
        // op CLI may return additional fields like "urls", "tags", etc.
        let json = r#"[
            {
                "id": "id1",
                "title": "Key 1",
                "vault": { "id": "v1", "name": "Work" },
                "category": "SSH_KEY",
                "additional_information": "SHA256:aaaa",
                "urls": [],
                "tags": ["ssh"],
                "favorite": false,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
        ]"#;

        let entries: Vec<OpItemListEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "id1");
    }

    // --- validate_item_id tests ---

    #[test]
    fn validate_item_id_accepts_alphanumeric() {
        assert!(validate_item_id("zl4nsgmrs73isw6mlc464tpecy").is_ok());
        assert!(validate_item_id("abc123").is_ok());
        assert!(validate_item_id("A").is_ok());
    }

    #[test]
    fn validate_item_id_rejects_empty() {
        assert!(validate_item_id("").is_err());
    }

    #[test]
    fn validate_item_id_rejects_flag_injection() {
        assert!(validate_item_id("--vault").is_err());
        assert!(validate_item_id("-h").is_err());
    }

    #[test]
    fn validate_item_id_rejects_special_chars() {
        assert!(validate_item_id("abc;rm -rf /").is_err());
        assert!(validate_item_id("abc def").is_err());
        assert!(validate_item_id("abc/def").is_err());
    }
}
