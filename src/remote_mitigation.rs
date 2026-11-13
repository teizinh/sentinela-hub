#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Active defense actions that can be dispatched to remote Sentinela sensor nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MitigationAction {
    BanIp { ip: String, duration_secs: u64 },
    UnbanIp { ip: String },
    DeployDecoyPort { port: u16 },
    IsolateSensor,
}

/// A mitigation command queued for a target sensor node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitigationCommand {
    pub command_id: String,
    pub target_node_id: String,
    pub action: MitigationAction,
    pub issued_at: u64,
    pub status: String,
}

impl MitigationCommand {
    /// Formats the command into a JSON payload ready for REST delivery.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserializes a command from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Distributed Mitigation Orchestrator that manages command queues and dispatching
/// active defense instructions to remote Sentinela sensor nodes.
#[derive(Debug, Clone)]
pub struct MitigationOrchestrator {
    commands: Vec<MitigationCommand>,
    next_sequence: u64,
}

impl Default for MitigationOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl MitigationOrchestrator {
    /// Creates a new distributed mitigation orchestrator instance.
    pub fn new() -> Self {
        Self {
            commands: Vec::new(),
            next_sequence: 1,
        }
    }

    /// Helper to get current Unix epoch in seconds.
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Helper to allocate a unique command ID.
    fn generate_command_id(&mut self) -> String {
        let id = format!("cmd-{}", self.next_sequence);
        self.next_sequence += 1;
        id
    }

    /// Issues an active defense Ban IP command for a specific sensor node.
    pub fn issue_ban(&mut self, target_node_id: &str, ip: &str, duration_secs: u64) -> MitigationCommand {
        let command = MitigationCommand {
            command_id: self.generate_command_id(),
            target_node_id: target_node_id.to_string(),
            action: MitigationAction::BanIp {
                ip: ip.to_string(),
                duration_secs,
            },
            issued_at: Self::current_timestamp(),
            status: "pending".to_string(),
        };

        self.commands.push(command.clone());
        command
    }

    /// Issues an active defense Unban IP command for a specific sensor node.
    pub fn issue_unban(&mut self, target_node_id: &str, ip: &str) -> MitigationCommand {
        let command = MitigationCommand {
            command_id: self.generate_command_id(),
            target_node_id: target_node_id.to_string(),
            action: MitigationAction::UnbanIp {
                ip: ip.to_string(),
            },
            issued_at: Self::current_timestamp(),
            status: "pending".to_string(),
        };

        self.commands.push(command.clone());
        command
    }

    /// Issues a command to deploy a dynamic honeypot/decoy port on the sensor node.
    pub fn issue_deploy_decoy_port(&mut self, target_node_id: &str, port: u16) -> MitigationCommand {
        let command = MitigationCommand {
            command_id: self.generate_command_id(),
            target_node_id: target_node_id.to_string(),
            action: MitigationAction::DeployDecoyPort { port },
            issued_at: Self::current_timestamp(),
            status: "pending".to_string(),
        };

        self.commands.push(command.clone());
        command
    }

    /// Issues an isolation command to instruct the sensor node to disconnect or isolate.
    pub fn issue_isolate_sensor(&mut self, target_node_id: &str) -> MitigationCommand {
        let command = MitigationCommand {
            command_id: self.generate_command_id(),
            target_node_id: target_node_id.to_string(),
            action: MitigationAction::IsolateSensor,
            issued_at: Self::current_timestamp(),
            status: "pending".to_string(),
        };

        self.commands.push(command.clone());
        command
    }

    /// Returns all pending mitigation commands destined for the given node.
    pub fn pending_commands_for_node(&self, node_id: &str) -> Vec<MitigationCommand> {
        self.commands
            .iter()
            .filter(|cmd| cmd.target_node_id == node_id && cmd.status == "pending")
            .cloned()
            .collect()
    }

    /// Acknowledges execution of a command from a sensor node, updating its status.
    pub fn acknowledge_command(&mut self, command_id: &str, success: bool) {
        if let Some(cmd) = self.commands.iter_mut().find(|c| c.command_id == command_id) {
            cmd.status = if success {
                "acknowledged".to_string()
            } else {
                "failed".to_string()
            };
        }
    }

    /// Formats a command into a JSON payload ready for REST delivery.
    pub fn format_command_json(&self, cmd: &MitigationCommand) -> Result<String, serde_json::Error> {
        serde_json::to_string(cmd)
    }

    /// Associated function to format any command into a JSON payload.
    pub fn command_to_json(cmd: &MitigationCommand) -> Result<String, serde_json::Error> {
        serde_json::to_string(cmd)
    }

    /// Retrieves an immutable reference to a command by its ID.
    pub fn get_command(&self, command_id: &str) -> Option<&MitigationCommand> {
        self.commands.iter().find(|c| c.command_id == command_id)
    }

    /// Returns a slice of all commands recorded in the orchestrator.
    pub fn all_commands(&self) -> &[MitigationCommand] {
        &self.commands
    }

    /// Total count of commands in the orchestrator.
    pub fn command_count(&self) -> usize {
        self.commands.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_ban_generation() {
        let mut orchestrator = MitigationOrchestrator::new();
        let cmd = orchestrator.issue_ban("sensor-alpha", "198.51.100.25", 7200);

        assert_eq!(cmd.target_node_id, "sensor-alpha");
        assert_eq!(cmd.status, "pending");
        assert_eq!(
            cmd.action,
            MitigationAction::BanIp {
                ip: "198.51.100.25".to_string(),
                duration_secs: 7200,
            }
        );
        assert!(!cmd.command_id.is_empty());
        assert!(cmd.issued_at > 0);

        // Orchestrator keeps command in state
        let retrieved = orchestrator.get_command(&cmd.command_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().target_node_id, "sensor-alpha");
    }

    #[test]
    fn test_orchestrator_node_queue_filtering() {
        let mut orchestrator = MitigationOrchestrator::new();

        let _cmd1 = orchestrator.issue_ban("node-01", "10.0.0.50", 1800);
        let _cmd2 = orchestrator.issue_unban("node-01", "10.0.0.51");
        let _cmd3 = orchestrator.issue_ban("node-02", "192.168.1.99", 3600);

        let node1_pending = orchestrator.pending_commands_for_node("node-01");
        assert_eq!(node1_pending.len(), 2);
        assert_eq!(node1_pending[0].target_node_id, "node-01");
        assert_eq!(node1_pending[1].target_node_id, "node-01");

        let node2_pending = orchestrator.pending_commands_for_node("node-02");
        assert_eq!(node2_pending.len(), 1);
        assert_eq!(node2_pending[0].target_node_id, "node-02");

        let node3_pending = orchestrator.pending_commands_for_node("node-03");
        assert!(node3_pending.is_empty());
    }

    #[test]
    fn test_acknowledgement_lifecycle() {
        let mut orchestrator = MitigationOrchestrator::new();
        let cmd = orchestrator.issue_ban("sensor-01", "203.0.113.10", 300);

        assert_eq!(orchestrator.pending_commands_for_node("sensor-01").len(), 1);
        assert_eq!(cmd.status, "pending");

        // Acknowledge with success
        orchestrator.acknowledge_command(&cmd.command_id, true);

        // Once acknowledged, it should no longer be pending
        let pending = orchestrator.pending_commands_for_node("sensor-01");
        assert!(pending.is_empty());

        let cmd_after = orchestrator.get_command(&cmd.command_id).unwrap();
        assert_eq!(cmd_after.status, "acknowledged");

        // Issue another command and acknowledge with failure
        let cmd_fail = orchestrator.issue_unban("sensor-01", "203.0.113.10");
        assert_eq!(orchestrator.pending_commands_for_node("sensor-01").len(), 1);

        orchestrator.acknowledge_command(&cmd_fail.command_id, false);
        assert!(orchestrator.pending_commands_for_node("sensor-01").is_empty());

        let cmd_fail_after = orchestrator.get_command(&cmd_fail.command_id).unwrap();
        assert_eq!(cmd_fail_after.status, "failed");
    }

    #[test]
    fn test_json_serialization() {
        let mut orchestrator = MitigationOrchestrator::new();
        let cmd = orchestrator.issue_ban("sensor-01", "198.51.100.77", 3600);

        let json_from_method = orchestrator.format_command_json(&cmd).unwrap();
        let json_from_cmd = cmd.to_json().unwrap();
        assert_eq!(json_from_method, json_from_cmd);

        // Deserialization check
        let deserialized: MitigationCommand = serde_json::from_str(&json_from_method).unwrap();
        assert_eq!(deserialized, cmd);

        // Ensure JSON contains essential keys
        assert!(json_from_method.contains("command_id"));
        assert!(json_from_method.contains("target_node_id"));
        assert!(json_from_method.contains("BanIp"));
        assert!(json_from_method.contains("198.51.100.77"));
        assert!(json_from_method.contains("3600"));
        assert!(json_from_method.contains("pending"));

        // Test other actions serialization
        let decoy_cmd = orchestrator.issue_deploy_decoy_port("sensor-02", 8080);
        let decoy_json = MitigationOrchestrator::command_to_json(&decoy_cmd).unwrap();
        assert!(decoy_json.contains("DeployDecoyPort"));
        assert!(decoy_json.contains("8080"));

        let isolate_cmd = orchestrator.issue_isolate_sensor("sensor-03");
        let isolate_json = isolate_cmd.to_json().unwrap();
        assert!(isolate_json.contains("IsolateSensor"));
    }

    #[test]
    fn test_decoy_and_isolate_actions() {
        let mut orchestrator = MitigationOrchestrator::new();
        let decoy = orchestrator.issue_deploy_decoy_port("node-x", 9999);
        assert_eq!(
            decoy.action,
            MitigationAction::DeployDecoyPort { port: 9999 }
        );
        assert_eq!(decoy.target_node_id, "node-x");

        let isolate = orchestrator.issue_isolate_sensor("node-x");
        assert_eq!(isolate.action, MitigationAction::IsolateSensor);
        assert_eq!(isolate.target_node_id, "node-x");

        assert_eq!(orchestrator.pending_commands_for_node("node-x").len(), 2);
    }
}
