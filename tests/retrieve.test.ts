import { describe, it, expect } from "vitest";
import {
    RBAC,
    RolesConfig,
    WILDCARD_PERMISSION,
    own,
    group,
    val,
} from "../src/rbac";

describe("RBAC Permission Retrieval", () => {
    // Setup test roles configuration with inheritance
    const setupTestRoles = (): RolesConfig => ({
        base: {
            name: "Base User",
            permissions: {
                posts: ["read"],
                comments: ["read"],
                resources: ["view"],
            },
            description: "Base user with minimal permissions",
        },
        member: {
            name: "Member",
            permissions: {
                posts: ["create:own"],
                comments: ["create:own"],
                profile: ["edit:own"],
            },
            description: "Regular member with own content creation",
            inherits: ["base"],
        },
        editor: {
            name: "Editor",
            permissions: {
                posts: ["update", "delete:own", "publish"],
                comments: ["update:own", "delete:own", "moderate"],
                categories: ["view", "assign"],
            },
            description: "Editor with content management capabilities",
            inherits: ["member"],
        },
        admin: {
            name: "Administrator",
            permissions: {
                users: ["view", "edit", "delete"],
                settings: ["view", "edit"],
                system: ["backup", "restore"],
            },
            description: "Administrator with system-level access",
            inherits: ["editor"],
        },
        superadmin: {
            name: "Super Administrator",
            permissions: {
                system: [WILDCARD_PERMISSION],
            },
            description: "Super administrator with complete system access",
            inherits: ["admin"],
        },
        moderator: {
            name: "Moderator",
            permissions: {
                posts: ["flag", "hide"],
                comments: ["flag", "hide", "delete"],
            },
            description: "Content moderator",
            inherits: ["member"],
        },
    });

    describe("Getting Direct Permissions", () => {
        it("should retrieve direct permissions for a role on a specific resource", () => {
            const rbac = new RBAC(setupTestRoles());

            // Access private getRolePermissions method for testing
            // Note: We use square bracket notation to access private methods in tests
            // This is why IntelliSense doesn't recognize the method
            // @ts-ignore - accessing private method for testing
            const editorPostPermissions = rbac["getRolePermissions"](
                "editor",
                "posts",
            );

            // Check direct permissions (not inherited)
            expect(editorPostPermissions).toContain("update");
            expect(editorPostPermissions).toContain("delete:own");
            expect(editorPostPermissions).toContain("publish");

            // Should not contain inherited permissions
            expect(editorPostPermissions).not.toContain("read");
            expect(editorPostPermissions).not.toContain("create:own");
        });

        it("should return empty array for non-existent roles or resources", () => {
            const rbac = new RBAC(setupTestRoles());

            // @ts-ignore - accessing private method for testing
            const nonExistentRolePermissions = rbac["getRolePermissions"](
                "nonexistent",
                "posts",
            );
            expect(nonExistentRolePermissions).toEqual([]);

            // @ts-ignore - accessing private method for testing
            const nonExistentResourcePermissions = rbac["getRolePermissions"](
                "editor",
                "nonexistent",
            );
            expect(nonExistentResourcePermissions).toEqual([]);
        });
    });

    describe("Getting All Permissions (Including Inherited)", () => {
        it("should retrieve all permissions for a role on a specific resource", () => {
            const rbac = new RBAC(setupTestRoles());

            // Using the public getAllPermissions method
            const adminPostPermissions = rbac.getAllPermissions(
                "admin",
                "posts",
            );

            // Should contain both direct and inherited permissions
            // From base
            expect(adminPostPermissions).toContain("read");
            // From member
            expect(adminPostPermissions).toContain("create:own");
            // From editor
            expect(adminPostPermissions).toContain("update");
            expect(adminPostPermissions).toContain("delete:own");
            expect(adminPostPermissions).toContain("publish");

            // Should not contain permissions from other roles not in the inheritance chain
            // From moderator (not in admin's inheritance chain)
            expect(adminPostPermissions).not.toContain("flag");
            expect(adminPostPermissions).not.toContain("hide");
        });

        it("should handle deep inheritance chains", () => {
            const rbac = new RBAC(setupTestRoles());

            const superadminCommentsPermissions = rbac.getAllPermissions(
                "superadmin",
                "comments",
            );

            // Should contain permissions from all levels
            // From base
            expect(superadminCommentsPermissions).toContain("read");
            // From member
            expect(superadminCommentsPermissions).toContain("create:own");
            // From editor
            expect(superadminCommentsPermissions).toContain("update:own");
            expect(superadminCommentsPermissions).toContain("delete:own");
            expect(superadminCommentsPermissions).toContain("moderate");
        });

        it("should return empty array for non-existent roles", () => {
            const rbac = new RBAC(setupTestRoles());

            const nonExistentRolePermissions = rbac.getAllPermissions(
                "nonexistent",
                "posts",
            );
            expect(nonExistentRolePermissions).toEqual([]);
        });

        it("should handle circular inheritance gracefully", () => {
            const rbac = new RBAC({
                role1: {
                    permissions: {
                        resource1: ["action1", "action2"],
                    },
                    inherits: ["role2"],
                },
                role2: {
                    permissions: {
                        resource1: ["action3", "action4"],
                    },
                    inherits: ["role1"],
                },
            });

            // Should handle circular inheritance without stack overflow
            const permissions = rbac.getAllPermissions("role1", "resource1");

            // Should contain permissions from both roles without duplicates
            expect(permissions).toContain("action1");
            expect(permissions).toContain("action2");
            expect(permissions).toContain("action3");
            expect(permissions).toContain("action4");
            expect(permissions.length).toBe(4); // No duplicates
        });
    });

    describe("Getting All Resource Permissions", () => {
        it("should retrieve permissions for all resources a role has access to", () => {
            const rbac = new RBAC(setupTestRoles());

            // Get all permissions for editor across all resources
            const editorPermissions = rbac.getAllResourcePermissions("editor");

            console.log(editorPermissions);

            // Should have entries for all resources editor has access to (direct and inherited)
            expect(Object.keys(editorPermissions)).toContain("posts");
            expect(Object.keys(editorPermissions)).toContain("comments");
            expect(Object.keys(editorPermissions)).toContain("categories");
            expect(Object.keys(editorPermissions)).toContain("resources"); // inherited from base
            expect(Object.keys(editorPermissions)).toContain("profile"); // inherited from member

            // Check specific permissions for each resource
            expect(editorPermissions.posts).toContain("update"); // direct
            expect(editorPermissions.posts).toContain("read"); // inherited from base
            expect(editorPermissions.posts).toContain("create:own"); // inherited from member

            expect(editorPermissions.comments).toContain("moderate"); // direct
            expect(editorPermissions.comments).toContain("read"); // inherited from base

            expect(editorPermissions.categories).toContain("view"); // direct
            expect(editorPermissions.categories).toContain("assign"); // direct

            expect(editorPermissions.profile).toContain("edit:own"); // inherited from member
        });

        it("should return empty object for non-existent roles", () => {
            const rbac = new RBAC(setupTestRoles());

            const nonExistentRolePermissions =
                rbac.getAllResourcePermissions("nonexistent");
            expect(nonExistentRolePermissions).toEqual({});
        });

        it("should correctly handle resources with wildcard permissions", () => {
            const rbac = new RBAC(setupTestRoles());

            const superadminPermissions =
                rbac.getAllResourcePermissions("superadmin");

            // System should have wildcard and specific permissions
            expect(superadminPermissions.system).toContain(WILDCARD_PERMISSION); // direct
            expect(superadminPermissions.system).toContain("backup"); // inherited from admin
            expect(superadminPermissions.system).toContain("restore"); // inherited from admin
        });
    });

    describe("Permission Checking with Inherited Permissions", () => {
        it("should check if a role has a specific permission via inheritance", () => {
            const rbac = new RBAC(setupTestRoles());

            // Admin inherits 'read' from base
            expect(rbac.can("admin", "read", "posts")).toBe(true);

            // Admin inherits 'create:own' from member
            expect(rbac.can("admin", "create:own", "posts")).toBe(true);

            // Admin inherits 'update' from editor
            expect(rbac.can("admin", "update", "posts")).toBe(true);
        });

        it("should handle ownership checks with inherited permissions", () => {
            const rbac = new RBAC(setupTestRoles());
            const userId = "user123";
            const ownedResourceId = "user123";
            const otherResourceId = "user456";

            // Admin inherits 'create:own' from member
            expect(
                rbac.can(
                    "admin",
                    own("create", userId, ownedResourceId),
                    "posts",
                ),
            ).toBe(true);
            expect(
                rbac.can(
                    "admin",
                    own("create", userId, otherResourceId),
                    "posts",
                ),
            ).toBe(false);

            // Admin inherits 'edit:own' from member
            expect(
                rbac.can(
                    "admin",
                    own("edit", userId, ownedResourceId),
                    "profile",
                ),
            ).toBe(true);
            expect(
                rbac.can(
                    "admin",
                    own("edit", userId, otherResourceId),
                    "profile",
                ),
            ).toBe(false);
        });

        it("should handle group permissions with inheritance", () => {
            const rbac = new RBAC({
                team: {
                    permissions: {
                        project: ["view", "edit:group"],
                    },
                },
                manager: {
                    permissions: {
                        reports: ["view", "generate"],
                    },
                    inherits: ["team"],
                },
            });

            const userId = "manager1";
            const teamMembers = ["manager1", "team1", "team2"];
            const otherTeam = ["team3", "team4"];

            // Manager inherits 'edit:group' from team role
            expect(
                rbac.can(
                    "manager",
                    group("edit", userId, teamMembers),
                    "project",
                ),
            ).toBe(true);
            expect(
                rbac.can(
                    "manager",
                    group("edit", userId, otherTeam),
                    "project",
                ),
            ).toBe(false);
        });

        it("should handle validation function permissions with inheritance", () => {
            const rbac = new RBAC({
                analyst: {
                    permissions: {
                        reports: ["view", "export:val"],
                    },
                },
                seniorAnalyst: {
                    permissions: {
                        data: ["modify", "delete"],
                    },
                    inherits: ["analyst"],
                },
            });

            // Senior analyst inherits 'export:val' from analyst
            expect(
                rbac.can(
                    "seniorAnalyst",
                    val("export", () => true),
                    "reports",
                ),
            ).toBe(true);
            expect(
                rbac.can(
                    "seniorAnalyst",
                    val("export", () => false),
                    "reports",
                ),
            ).toBe(false);
        });
    });

    describe("Wildcard Permissions", () => {
        it("should properly handle wildcard permissions with getAllPermissions", () => {
            const rbac = new RBAC(setupTestRoles());

            const superadminSystemPermissions = rbac.getAllPermissions(
                "superadmin",
                "system",
            );

            // Should contain both wildcard and specific permissions
            expect(superadminSystemPermissions).toContain(WILDCARD_PERMISSION);
            expect(superadminSystemPermissions).toContain("backup"); // Inherited from admin
            expect(superadminSystemPermissions).toContain("restore"); // Inherited from admin
        });

        it("should allow any action on a resource with wildcard permission", () => {
            const rbac = new RBAC(setupTestRoles());

            // Check arbitrary actions on system for superadmin (has wildcard)
            expect(rbac.can("superadmin", "anyAction", "system")).toBe(true);
            expect(rbac.can("superadmin", "anotherAction", "system")).toBe(
                true,
            );

            // Check that wildcard is limited to the specific resource
            expect(
                rbac.can("superadmin", "randomAction", "nonexistentResource"),
            ).toBe(false);
        });
    });

    describe("Permission Explanation with Inheritance", () => {
        it("should explain permissions granted through inheritance", () => {
            const rbac = new RBAC(setupTestRoles());

            // Admin inherits 'read' from base
            const explanation = rbac.canExplain("admin", "read", "posts");

            expect(explanation).toHaveProperty("granted", true);
            expect(explanation).toHaveProperty("role", "admin");
            expect(explanation).toHaveProperty("resource", "posts");
            expect(explanation).toHaveProperty("action", "read");
        });

        it("should explain ownership permissions with inheritance", () => {
            const rbac = new RBAC(setupTestRoles());
            const userId = "user123";
            const otherResourceId = "user456";

            // Admin inherits 'create:own' from member, but ownership check fails
            const explanation = rbac.canExplain(
                "admin",
                own("create", userId, otherResourceId),
                "posts",
            );

            expect(explanation).toHaveProperty("granted", false);
            expect(explanation).toHaveProperty(
                "reason",
                "OWNERSHIP_CHECK_FAILED",
            );
            expect(explanation).toHaveProperty("role", "admin");
            expect(explanation).toHaveProperty("resource", "posts");
            expect(explanation).toHaveProperty("action", "create");
            expect(explanation).toHaveProperty("ownership", "own");
        });
    });
});
