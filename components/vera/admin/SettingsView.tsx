import { useState, useEffect } from "react";
import {
  Bell,
  Users,
  Database,
  Globe,
  Mail,
  Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { AlertDialog, AlertDialogContent, AlertDialogHeader, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter, AlertDialogCancel } from "@/components/ui/alert-dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { motion } from "motion/react";
import { RoutingRulesEditor } from "./RoutingRulesEditor";
import { CounselBench } from "./CounselBench";

const ink = (pct: number) =>
  `color-mix(in srgb, var(--vera-ink) calc(${pct}% * var(--vera-ink-boost)), transparent)`;

type TeamMember = {
  user_id: string;
  email: string;
  name: string;
  role: string;
};

interface SettingsViewProps {
  isAdmin?: boolean;
}

export function SettingsView({ isAdmin = false }: SettingsViewProps) {
  const [criticalAlerts, setCriticalAlerts] = useState(true);
  const [weeklyDigest, setWeeklyDigest] = useState(false);
  const [dataRetention, setDataRetention] = useState("90");

  // Team management state
  const [teamMembers, setTeamMembers] = useState<TeamMember[]>([]);
  const [teamLoading, setTeamLoading] = useState(true);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("employee");
  const [inviting, setInviting] = useState(false);
  const [pendingRemoval, setPendingRemoval] = useState<TeamMember | null>(null);
  const [removing, setRemoving] = useState(false);
  const [removalError, setRemovalError] = useState("");

  // Fetch team members on mount
  useEffect(() => {
    setTeamLoading(true);
    fetch("/api/admin/users")
      .then((res) => res.json())
      .then((data) => {
        if (data.success && Array.isArray(data.users)) {
          setTeamMembers(data.users);
        }
      })
      .catch(() => {})
      .finally(() => setTeamLoading(false));
  }, []);

  const handleInvite = async () => {
    if (!inviteEmail.trim()) return;
    setInviting(true);
    try {
      const res = await fetch("/api/admin/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: inviteEmail, role: inviteRole }),
      });
      const data = await res.json();
      if (data.success && data.user) {
        setTeamMembers((prev) => [...prev, data.user]);
        setInviteEmail("");
        if (data.inviteEmailSent) {
          alert(`Invite sent! ${inviteEmail} will receive an email with instructions.`);
        } else {
          const reason = data.inviteEmailError ? `\n\nReason: ${data.inviteEmailError}` : '';
          alert(`User created, but the invite email could not be sent. Please share the login details manually.${reason}`);
        }
      } else {
        alert(data.error || "Failed to invite user");
      }
    } catch {
      alert("Failed to invite user");
    } finally {
      setInviting(false);
    }
  };

  const handleRoleChange = async (userId: string, newRole: string) => {
    try {
      const res = await fetch(`/api/admin/users/${userId}/role`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ role: newRole }),
      });
      const data = await res.json();
      if (data.success) {
        setTeamMembers((prev) =>
          prev.map((m) => (m.user_id === userId ? { ...m, role: newRole } : m)),
        );
      } else {
        alert(data.error || "Failed to change role");
      }
    } catch {
      alert("Failed to change role");
    }
  };

  const handleRemoveUser = async () => {
    if (!isAdmin || !pendingRemoval || removing) return;
    const userId = pendingRemoval.user_id;
    setRemoving(true);
    setRemovalError("");
    try {
      const res = await fetch(`/api/admin/users/${encodeURIComponent(userId)}`, { method: "DELETE" });
      const data = await res.json();
      if (res.ok && data.success) {
        setTeamMembers((prev) => prev.filter((m) => m.user_id !== userId));
        setPendingRemoval(null);
      } else {
        setRemovalError(data.error || "Failed to remove user. Please try again.");
      }
    } catch {
      setRemovalError("Failed to remove user. Please try again.");
    } finally {
      setRemoving(false);
    }
  };

  const cardStyle = { backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
      className="pb-8"
    >
      <AlertDialog open={pendingRemoval !== null} onOpenChange={(open) => {
        if (!open && !removing) { setPendingRemoval(null); setRemovalError(""); }
      }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove team member?</AlertDialogTitle>
            <AlertDialogDescription>
              {pendingRemoval?.name || pendingRemoval?.email} will lose access to this team.
            </AlertDialogDescription>
          </AlertDialogHeader>
          {removalError && <p role="alert" className="text-sm text-red-600">{removalError}</p>}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={removing}>Cancel</AlertDialogCancel>
            <Button type="button" variant="destructive" onClick={handleRemoveUser} disabled={removing}>
              {removing ? "Removing…" : "Remove team member"}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      {/* Header */}
      <div className="mb-6">
        <h2 className="mb-1" style={{ fontSize: "1.1rem", fontWeight: 500, color: ink(80) }}>
          Settings
        </h2>
        <p style={{ fontSize: "13px", color: ink(45) }}>
          Configure your admin preferences
        </p>
      </div>

      {/* Cards grid: 2 cols on md+, 1 on small */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Notifications */}
        <div className="p-6 transition-colors duration-500 md:min-h-0" style={cardStyle}>
        <div className="flex items-center gap-2 mb-5">
          <Bell className="size-4" style={{ color: ink(45) }} />
          <h3 style={{ fontSize: "14px", fontWeight: 500, color: ink(70) }}>
            Notifications
          </h3>
        </div>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p style={{ fontSize: "13px", color: ink(55) }}>
                Critical Alerts
              </p>
              <p className="mt-0.5" style={{ fontSize: "12px", color: ink(45) }}>
                Instant push notifications for high-priority reports
              </p>
            </div>
            <Switch checked={criticalAlerts} onCheckedChange={setCriticalAlerts} />
          </div>
          <div style={{ borderTop: `1px solid ${ink(4)}` }} />
          <div className="flex items-center justify-between">
            <div>
              <p style={{ fontSize: "13px", color: ink(55) }}>
                Weekly Digest
              </p>
              <p className="mt-0.5" style={{ fontSize: "12px", color: ink(45) }}>
                Summary of all reports delivered every Monday
              </p>
            </div>
            <Switch checked={weeklyDigest} onCheckedChange={setWeeklyDigest} />
          </div>
        </div>
        </div>

        {/* Data & Privacy */}
        <div className="p-6 transition-colors duration-500 md:min-h-0" style={cardStyle}>
        <div className="flex items-center gap-2 mb-5">
          <Database className="size-4" style={{ color: ink(45) }} />
          <h3 style={{ fontSize: "14px", fontWeight: 500, color: ink(70) }}>
            Data & Privacy
          </h3>
        </div>
        <div className="space-y-4">
          <div>
            <Label className="mb-2 block" style={{ fontSize: "12px", color: ink(40) }}>
              Data Retention (days)
            </Label>
            <Input
              type="number"
              value={dataRetention}
              onChange={(e) => setDataRetention(e.target.value)}
              className="w-32 rounded-none focus-visible:ring-0"
              style={{ borderColor: ink(6), backgroundColor: ink(2), color: ink(60) }}
            />
            <p className="mt-1.5" style={{ fontSize: "11px", color: ink(45) }}>
              Reports older than this will be automatically archived
            </p>
          </div>
        </div>
        </div>

        {/* Team Management — full width so the grid stays balanced */}
        <div className="p-6 transition-colors duration-500 md:col-span-2" style={cardStyle}>
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <Users className="size-4" style={{ color: ink(45) }} />
            <h3 style={{ fontSize: "14px", fontWeight: 500, color: ink(70) }}>
              Team Members
            </h3>
          </div>
        </div>

        {/* Invite form — admin only */}
        {isAdmin && (
          <div className="flex gap-2 mb-4">
            <Input
              type="email"
              placeholder="Email address"
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              className="flex-1 rounded-none focus-visible:ring-0"
              style={{ borderColor: ink(6), backgroundColor: ink(2), color: ink(60), fontSize: "12px" }}
            />
            <Select value={inviteRole} onValueChange={setInviteRole}>
              <SelectTrigger
                className="w-[120px] rounded-none"
                style={{ borderColor: ink(6), backgroundColor: ink(2), color: ink(50), fontSize: "11px" }}
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="admin">Admin</SelectItem>
                <SelectItem value="employee">Employee</SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant="outline"
              size="sm"
              className="rounded-none"
              style={{ borderColor: ink(6), color: ink(40), fontSize: "11px" }}
              onClick={handleInvite}
              disabled={inviting || !inviteEmail.trim()}
            >
              {inviting ? "Inviting..." : "Invite"}
            </Button>
          </div>
        )}

        <div className="space-y-2">
          {teamLoading ? (
            <p style={{ fontSize: "12px", color: ink(45) }}>Loading team...</p>
          ) : teamMembers.length === 0 ? (
            <p style={{ fontSize: "12px", color: ink(45) }}>No team members found</p>
          ) : (
            teamMembers.map((member) => (
              <div
                key={member.user_id}
                className="flex items-center justify-between p-3"
                style={{ backgroundColor: ink(2), border: `1px solid ${ink(4)}` }}
              >
                <div className="flex items-center gap-3">
                  <div className="size-8 flex items-center justify-center" style={{ backgroundColor: ink(6), fontSize: "11px" }}>
                    <span style={{ color: ink(40) }}>{(member.name || member.email).charAt(0).toUpperCase()}</span>
                  </div>
                  <div>
                    <p style={{ fontSize: "13px", color: ink(55) }}>{member.name || member.email}</p>
                    <p style={{ fontSize: "11px", color: ink(45) }}>{member.email}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {isAdmin ? (
                    <>
                      <Select
                        value={member.role}
                        onValueChange={(val) => handleRoleChange(member.user_id, val)}
                      >
                        <SelectTrigger
                          className="w-[110px] h-7 rounded-none"
                          style={{ borderColor: ink(6), backgroundColor: ink(3), color: ink(50), fontSize: "10px" }}
                        >
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="admin">Admin</SelectItem>
                          <SelectItem value="employee">Employee</SelectItem>
                        </SelectContent>
                      </Select>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="size-7 p-0"
                        aria-label={`Remove ${member.name || member.email}`}
                        onClick={() => { setRemovalError(""); setPendingRemoval(member); }}
                      >
                        <Trash2 className="size-3.5 text-red-400/60" />
                      </Button>
                    </>
                  ) : (
                    <span
                      className="px-2 py-0.5"
                      style={{ fontSize: "10px", backgroundColor: ink(3), border: `1px solid ${ink(4)}`, color: ink(45) }}
                    >
                      {member.role.charAt(0).toUpperCase() + member.role.slice(1)}
                    </span>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
        </div>

        {/* Integrations — full width on all breakpoints */}
        <div className="p-6 transition-colors duration-500 md:col-span-2" style={cardStyle}>
        <div className="flex items-center gap-2 mb-5">
          <Globe className="size-4" style={{ color: ink(45) }} />
          <h3 style={{ fontSize: "14px", fontWeight: 500, color: ink(70) }}>
            Integrations
          </h3>
        </div>
        <div className="space-y-3">
          {[
            { name: "Email Forwarding", icon: Mail, status: "Connected", connected: true },
            { name: "Supabase", icon: Database, status: "Not configured", connected: false },
          ].map((integration) => (
            <div
              key={integration.name}
              className="flex items-center justify-between p-3"
              style={{ backgroundColor: ink(2), border: `1px solid ${ink(4)}` }}
            >
              <div className="flex items-center gap-3">
                <integration.icon className="size-4" style={{ color: ink(45) }} />
                <span style={{ fontSize: "13px", color: ink(55) }}>{integration.name}</span>
              </div>
              <span
                className={integration.connected ? "text-emerald-400" : ""}
                style={{ fontSize: "11px", ...(!integration.connected ? { color: ink(45) } : {}) }}
              >
                {integration.status}
              </span>
            </div>
          ))}
        </div>
        </div>
      </div>

      {isAdmin && (
        <div className="mt-6">
          <RoutingRulesEditor />
        </div>
      )}

      {isAdmin && (
        <div className="mt-6">
          <CounselBench />
        </div>
      )}

      {/* Save — page-level action with clear separation */}
      <div
        className="flex justify-end pt-6 mt-6"
        style={{ borderTop: `1px solid ${ink(4)}` }}
      >
        <Button
          className="rounded-none px-8 hover:opacity-90"
          style={{ fontSize: "11px", letterSpacing: "0.1em", textTransform: "uppercase", backgroundColor: "var(--vera-ink)", color: "var(--vera-paper)" }}
        >
          Save Changes
        </Button>
      </div>
    </motion.div>
  );
}
