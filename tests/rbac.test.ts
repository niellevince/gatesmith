import { describe, it, expect } from "vitest";
import {
    RBAC,
    RolesConfig,
    WILDCARD_PERMISSION,
    own,
    group,
    val,
} from "../src/rbac";

describe("RBAC", () => {
    // Setup test roles configuration
    const setupTestRoles = (): RolesConfig => ({
        admin: {
            name: "Administrator",
            permissions: {
                posts: ["create", "update", "read", "delete"],
                users: ["create", "update", "read", "delete"],
                comments: ["create", "update", "read", "delete"],
            },
            description:
                "System administrator with full access to most resources",
        },
        superadmin: {
            name: "Super Administrator",
            permissions: {
                system: [WILDCARD_PERMISSION],
                posts: [WILDCARD_PERMISSION],
                users: [WILDCARD_PERMISSION],
            },
            description: "Super administrator with complete system access",
        },
        editor: {
            name: "Content Editor",
            permissions: {
                posts: ["create:own", "update:own", "read", "delete:own"],
            },
            description: "Content editor with management of own content",
        },
        user: {
            name: "Regular User",
            permissions: {
                posts: ["create:own", "update:own", "read", "delete:own"],
                users: ["read:own"],
            },
            description: "Standard user account",
        },
        guest: {
            name: "Guest User",
            permissions: {
                posts: ["read"],
            },
            description: "Unauthenticated guest with limited access",
        },
    });

    describe("Basic Permission Checks", () => {
        it("should allow actions with simple permissions", () => {
            const rbac = new RBAC(setupTestRoles());

            expect(rbac.can("admin", "create", "posts")).toBe(true);
            expect(rbac.can("admin", "read", "posts")).toBe(true);
            expect(rbac.can("admin", "update", "posts")).toBe(true);
            expect(rbac.can("admin", "delete", "posts")).toBe(true);

            expect(rbac.can("user", "read", "posts")).toBe(true);
            expect(rbac.can("guest", "read", "posts")).toBe(true);
        });

        it("should deny actions without permissions", () => {
            const rbac = new RBAC(setupTestRoles());

            expect(rbac.can("guest", "create", "posts")).toBe(false);
            expect(rbac.can("guest", "update", "posts")).toBe(false);
            expect(rbac.can("guest", "delete", "posts")).toBe(false);

            expect(rbac.can("user", "create", "posts")).toBe(false);
            expect(rbac.can("user", "update", "posts")).toBe(false);
            expect(rbac.can("user", "delete", "posts")).toBe(false);
        });

        it("should handle non-existent roles and resources", () => {
            const rbac = new RBAC(setupTestRoles());

            expect(rbac.can("nonexistent", "read", "posts")).toBe(false);
            expect(rbac.can("user", "read", "nonexistent")).toBe(false);
        });
    });

    describe("Ownership Checks", () => {
        const userId = "user1";
        const ownedResourceId = "user1";
        const otherResourceId = "user2";

        it("should allow actions on own resources", () => {
            const rbac = new RBAC(setupTestRoles());

            expect(
                rbac.can(
                    "user",
                    own("update", userId, ownedResourceId),
                    "posts",
                ),
            ).toBe(true);
            expect(
                rbac.can(
                    "editor",
                    own("update", userId, ownedResourceId),
                    "posts",
                ),
            ).toBe(true);
            expect(
                rbac.can(
                    "user",
                    own("delete", userId, ownedResourceId),
                    "posts",
                ),
            ).toBe(true);
        });

        it("should deny actions on other resources", () => {
            const rbac = new RBAC(setupTestRoles());

            expect(
                rbac.can(
                    "user",
                    own("update", userId, otherResourceId),
                    "posts",
                ),
            ).toBe(false);
            expect(
                rbac.can(
                    "editor",
                    own("update", userId, otherResourceId),
                    "posts",
                ),
            ).toBe(false);
            expect(
                rbac.can(
                    "user",
                    own("delete", userId, otherResourceId),
                    "posts",
                ),
            ).toBe(false);
        });

        it("should allow admin actions on any resource", () => {
            const rbac = new RBAC(setupTestRoles());

            // Admin has general permission so can act on any resource regardless of ownership
            expect(
                rbac.can(
                    "admin",
                    own("update", userId, otherResourceId),
                    "posts",
                ),
            ).toBe(true);
            expect(
                rbac.can(
                    "admin",
                    own("delete", userId, otherResourceId),
                    "posts",
                ),
            ).toBe(true);
        });

        it("should respect ownership limitations for users", () => {
            const rbac = new RBAC(setupTestRoles());

            // User can read users, but only their own user profile
            expect(rbac.can("user", "read", "users")).toBe(false);
            expect(
                rbac.can("user", own("read", userId, ownedResourceId), "users"),
            ).toBe(true);
            expect(
                rbac.can("user", own("read", userId, otherResourceId), "users"),
            ).toBe(false);
        });
    });

    describe("Wildcard Permissions", () => {
        it("should grant any permission with wildcard", () => {
            const rbac = new RBAC(setupTestRoles());

            expect(rbac.can("superadmin", "create", "system")).toBe(true);
            expect(rbac.can("superadmin", "read", "system")).toBe(true);
            expect(rbac.can("superadmin", "update", "system")).toBe(true);
            expect(rbac.can("superadmin", "delete", "system")).toBe(true);
            expect(rbac.can("superadmin", "someRandomAction", "system")).toBe(
                true,
            );

            expect(rbac.hasWildcardPermission("superadmin", "system")).toBe(
                true,
            );
            expect(rbac.hasWildcardPermission("admin", "system")).toBe(false);
        });

        it("should respect ownership checks with wildcard", () => {
            const rbac = new RBAC(setupTestRoles());
            const userId = "user1";
            const otherResourceId = "user2";

            // When checking wildcard with ownership, if the comparison result is "true", it should return true
            expect(
                rbac.can("superadmin", own("update", userId, userId), "posts"),
            ).toBe(true);

            // When checking wildcard with ownership, if the comparison result is "false", it should return false
            // This is expected behavior - even wildcard permissions respect ownership checks
            expect(
                rbac.can(
                    "superadmin",
                    own("update", userId, otherResourceId),
                    "posts",
                ),
            ).toBe(false);
        });
    });

    describe("Permission Arrays", () => {
        it("should allow if any permission in array is granted", () => {
            const rbac = new RBAC(setupTestRoles());
            const userId = "user1";
            const ownedResourceId = "user1";
            const otherResourceId = "user2";

            // Should pass because 'read' is allowed
            expect(
                rbac.can("user", ["create", "read", "update"], "posts"),
            ).toBe(true);

            // Should pass because update:own with correct ownership is allowed
            expect(
                rbac.can(
                    "user",
                    ["create", own("update", userId, ownedResourceId)],
                    "posts",
                ),
            ).toBe(true);

            // Should fail because neither is allowed
            expect(
                rbac.can("user", ["create", "update", "delete"], "posts"),
            ).toBe(false);

            // Should fail because own check fails
            expect(
                rbac.can(
                    "user",
                    [
                        own("update", userId, otherResourceId),
                        own("delete", userId, otherResourceId),
                    ],
                    "posts",
                ),
            ).toBe(false);
        });
    });

    describe("Explanation System", () => {
        it("should explain permission grants", () => {
            const rbac = new RBAC(setupTestRoles());

            const explanation = rbac.canExplain("admin", "update", "posts");
            expect(explanation).toHaveProperty("granted", true);
            expect(explanation).toHaveProperty("reason", "PERMISSION_GRANTED");
        });

        it("should explain permission denials", () => {
            const rbac = new RBAC(setupTestRoles());

            const explanation = rbac.canExplain("guest", "update", "posts");
            expect(explanation).toHaveProperty("granted", false);
            expect(explanation).toHaveProperty("reason", "ACTION_NOT_ALLOWED");
        });

        it("should explain ownership-specific permissions", () => {
            const rbac = new RBAC(setupTestRoles());
            const userId = "user1";

            // REQUIRES_OWNERSHIP is a special reason we added in our fix
            const explanation = rbac.canExplain("user", "read", "users");
            expect(explanation).toHaveProperty("granted", false);
            expect(explanation).toHaveProperty("reason", "REQUIRES_OWNERSHIP");

            const ownershipPass = rbac.canExplain(
                "user",
                own("read", userId, userId),
                "users",
            );
            expect(ownershipPass).toHaveProperty("granted", true);

            const ownershipFail = rbac.canExplain(
                "user",
                own("read", userId, "other"),
                "users",
            );
            expect(ownershipFail).toHaveProperty("granted", false);
            expect(ownershipFail).toHaveProperty(
                "reason",
                "OWNERSHIP_CHECK_FAILED",
            );
        });
    });

    describe("Role Management", () => {
        it("should get role names", () => {
            const rbac = new RBAC(setupTestRoles());

            expect(rbac.getName("admin")).toBe("Administrator");
            expect(rbac.getName("user")).toBe("Regular User");
            expect(rbac.getName("nonexistent")).toBe("nonexistent");
        });

        it("should list all roles", () => {
            const rbac = new RBAC(setupTestRoles());
            const roles = rbac.getRoles();

            expect(roles).toContain("admin");
            expect(roles).toContain("user");
            expect(roles).toContain("guest");
            expect(roles).toContain("editor");
            expect(roles).toContain("superadmin");
            expect(roles.length).toBe(5);
        });
    });

    describe("Dynamic Role Updates", () => {
        it("should update existing roles", () => {
            const rbac = new RBAC(setupTestRoles());

            // Initially guest can't update posts
            expect(rbac.can("guest", "update", "posts")).toBe(false);

            // Update the guest role
            rbac.updateRoles({
                guest: {
                    permissions: {
                        posts: ["read", "update"],
                    },
                },
            });

            // Now guest can update posts
            expect(rbac.can("guest", "update", "posts")).toBe(true);
        });

        it("should add new roles", () => {
            const rbac = new RBAC(setupTestRoles());

            // Add a new role
            rbac.updateRoles({
                developer: {
                    name: "Developer",
                    permissions: {
                        system: ["read", "debug"],
                        logs: ["read", "download"],
                    },
                },
            });

            // Check the new role exists and has permissions
            const roles = rbac.getRoles();
            expect(roles).toContain("developer");
            expect(rbac.can("developer", "debug", "system")).toBe(true);
            expect(rbac.can("developer", "read", "logs")).toBe(true);
            expect(rbac.getName("developer")).toBe("Developer");
        });
    });

    describe("Group Check Functions", () => {
        it("should handle group membership checks", () => {
            const rbac = new RBAC({
                moderator: {
                    name: "Moderator",
                    permissions: {
                        "group-chat": ["moderate"],
                    },
                },
                user: {
                    name: "User",
                    permissions: {
                        "group-chat": ["read", "update:group"],
                    },
                },
            });

            const userId = "user1";
            const groupMembers = ["user1", "user2", "user3"];
            const nonMembers = ["user4", "user5"];

            // User can update group-chat if they're a member
            expect(
                rbac.can(
                    "user",
                    group("update", userId, groupMembers),
                    "group-chat",
                ),
            ).toBe(true);
            expect(
                rbac.can(
                    "user",
                    group("update", "user4", groupMembers),
                    "group-chat",
                ),
            ).toBe(false);

            // Moderators can moderate regardless of membership
            expect(rbac.can("moderator", "moderate", "group-chat")).toBe(true);
        });
    });

    describe("Custom Validation Functions", () => {
        it("should use custom validation functions", () => {
            const rbac = new RBAC({
                editor: {
                    permissions: {
                        reports: ["generate:val"],
                    },
                },
            });

            // Test with validation function that returns true
            const validationTrue = () => true;
            expect(
                rbac.can("editor", val("generate", validationTrue), "reports"),
            ).toBe(true);

            // Test with validation function that returns false
            const validationFalse = () => false;
            expect(
                rbac.can("editor", val("generate", validationFalse), "reports"),
            ).toBe(false);
        });
    });

    describe("Permission Pattern Checks with has()", () => {
        it("should check if role has a specific permission pattern", () => {
            const rbac = new RBAC(setupTestRoles());

            // Admin has general update permission
            expect(rbac.has("admin", "update", "posts")).toBe(true);

            // User has update:own but not general update
            expect(rbac.has("user", "update:own", "posts")).toBe(true);
            expect(rbac.has("user", "update", "posts")).toBe(false);

            // Guest has read but not update
            expect(rbac.has("guest", "read", "posts")).toBe(true);
            expect(rbac.has("guest", "update", "posts")).toBe(false);
        });

        it("should handle wildcard permissions correctly", () => {
            const rbac = new RBAC(setupTestRoles());

            // Superadmin has wildcard on posts
            expect(rbac.has("superadmin", "anyaction", "posts")).toBe(true);
            expect(rbac.has("superadmin", "update", "posts")).toBe(true);
            expect(rbac.has("superadmin", "update:own", "posts")).toBe(true);

            // Admin doesn't have wildcard
            expect(rbac.has("admin", "nonexistent", "posts")).toBe(false);
        });

        it("should handle general vs specific permission types correctly", () => {
            const rbac = new RBAC(setupTestRoles());

            // If looking for action:own but role has general action
            expect(rbac.has("admin", "update:own", "posts")).toBe(true);

            // If looking for general action but role only has action:own
            expect(rbac.has("user", "update", "posts")).toBe(false);
        });
    });
});
