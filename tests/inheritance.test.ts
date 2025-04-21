import { describe, it, expect } from "vitest";
import { RBAC, RolesConfig, WILDCARD_PERMISSION, own } from "../src/rbac";

describe("RBAC Role Inheritance", () => {
    // Setup test roles configuration with inheritance
    const setupRolesWithInheritance = (): RolesConfig => ({
        base: {
            name: "Base User",
            permissions: {
                posts: ["read"],
                comments: ["read"],
            },
            description: "Base user with minimal permissions",
        },
        member: {
            name: "Member",
            permissions: {
                posts: ["create:own"],
                comments: ["create:own"],
            },
            description: "Regular member with own content creation",
            inherits: ["base"], // Member inherits from base
        },
        editor: {
            name: "Editor",
            permissions: {
                posts: ["update", "delete:own"],
                comments: ["update:own", "delete:own"],
                categories: ["read"],
            },
            description: "Editor with content management capabilities",
            inherits: ["member"], // Editor inherits from member
        },
        admin: {
            name: "Administrator",
            permissions: {
                settings: ["read", "update"],
                users: ["read"],
            },
            description: "Administrator with system settings access",
            inherits: ["editor"], // Admin inherits from editor
        },
        superadmin: {
            name: "Super Administrator",
            permissions: {
                system: [WILDCARD_PERMISSION],
                users: ["create", "update", "delete"],
            },
            description: "Super administrator with complete access",
            inherits: ["admin"], // Superadmin inherits from admin
        },
        // Role with multiple inheritance
        moderator: {
            name: "Moderator",
            permissions: {
                comments: ["update", "delete"],
                posts: ["flag"],
            },
            description: "Content moderator",
            inherits: ["member"], // Moderator inherits from member
        },
        // Role with multiple inheritance paths
        seniorModerator: {
            name: "Senior Moderator",
            permissions: {
                users: ["ban"],
                categories: ["update"],
            },
            description:
                "Senior content moderator with additional capabilities",
            inherits: ["moderator", "editor"], // Inherits from both moderator and editor
        },
    });

    describe("Basic Inheritance", () => {
        it("should inherit permissions from parent roles", () => {
            const rbac = new RBAC(setupRolesWithInheritance());

            // Member inherits 'read' from base
            expect(rbac.can("member", "read", "posts")).toBe(true);
            expect(rbac.can("member", "read", "comments")).toBe(true);

            // Editor inherits from member, which inherits from base
            expect(rbac.can("editor", "read", "posts")).toBe(true);
            expect(rbac.can("editor", "create:own", "posts")).toBe(true);
        });

        it("should verify parent roles with getParentRoles method", () => {
            const rbac = new RBAC(setupRolesWithInheritance());

            expect(rbac.getParentRoles("base")).toEqual([]);
            expect(rbac.getParentRoles("member")).toEqual(["base"]);
            expect(rbac.getParentRoles("editor")).toEqual(["member"]);
            expect(rbac.getParentRoles("admin")).toEqual(["editor"]);
        });
    });

    describe("Multi-level Inheritance", () => {
        it("should inherit through multiple levels", () => {
            const rbac = new RBAC(setupRolesWithInheritance());

            // Admin should inherit all the way down the chain
            expect(rbac.can("admin", "read", "posts")).toBe(true); // from base
            expect(rbac.can("admin", "create:own", "posts")).toBe(true); // from member
            expect(rbac.can("admin", "update", "posts")).toBe(true); // from editor
            expect(rbac.can("admin", "read", "settings")).toBe(true); // directly on admin
        });

        it("should handle deep inheritance chains", () => {
            const rbac = new RBAC(setupRolesWithInheritance());

            // Superadmin inherits through 4 levels
            expect(rbac.can("superadmin", "read", "posts")).toBe(true); // from base
            expect(rbac.can("superadmin", "create:own", "comments")).toBe(true); // from member
            expect(rbac.can("superadmin", "update", "posts")).toBe(true); // from editor
            expect(rbac.can("superadmin", "read", "settings")).toBe(true); // from admin
            expect(rbac.can("superadmin", "create", "users")).toBe(true); // directly on superadmin
        });
    });

    describe("Multiple Inheritance", () => {
        it("should handle multiple inheritance paths", () => {
            const rbac = new RBAC(setupRolesWithInheritance());

            // Senior Moderator inherits from both moderator and editor

            // From moderator
            expect(rbac.can("seniorModerator", "update", "comments")).toBe(
                true,
            );
            expect(rbac.can("seniorModerator", "delete", "comments")).toBe(
                true,
            );
            expect(rbac.can("seniorModerator", "flag", "posts")).toBe(true);

            // From editor
            expect(rbac.can("seniorModerator", "update", "posts")).toBe(true);
            expect(rbac.can("seniorModerator", "delete:own", "posts")).toBe(
                true,
            );
            expect(rbac.can("seniorModerator", "read", "categories")).toBe(
                true,
            );

            // Senior Moderator's own permissions
            expect(rbac.can("seniorModerator", "ban", "users")).toBe(true);
            expect(rbac.can("seniorModerator", "update", "categories")).toBe(
                true,
            );

            // Inherited from base (via both moderator and editor paths)
            expect(rbac.can("seniorModerator", "read", "posts")).toBe(true);
            expect(rbac.can("seniorModerator", "read", "comments")).toBe(true);
        });

        it("should not have duplicate permissions when inheriting from multiple paths", () => {
            const rbac = new RBAC(setupRolesWithInheritance());

            // Get all permissions for seniorModerator on posts
            const permissions = rbac["getAllPermissions"](
                "seniorModerator",
                "posts",
            );

            // Count occurrences of 'read' permission
            const readCount = permissions.filter((p) => p === "read").length;

            // Despite inheriting 'read' from multiple paths, it should only appear once
            expect(readCount).toBe(1);
        });
    });

    describe("Ownership Checks with Inheritance", () => {
        const userId = "user1";
        const ownPostId = "user1";
        const otherPostId = "user2";

        it("should respect ownership checks with inherited permissions", () => {
            const rbac = new RBAC(setupRolesWithInheritance());

            // Member inherits read from base, but has create:own directly
            expect(rbac.can("member", "read", "posts")).toBe(true);
            expect(
                rbac.can("member", own("create", userId, ownPostId), "posts"),
            ).toBe(true);
            expect(
                rbac.can("member", own("create", userId, otherPostId), "posts"),
            ).toBe(false);

            // Editor has update (general) directly
            expect(rbac.can("editor", "update", "posts")).toBe(true);
            expect(
                rbac.can("editor", own("update", userId, ownPostId), "posts"),
            ).toBe(true);
            expect(
                rbac.can("editor", own("update", userId, otherPostId), "posts"),
            ).toBe(true);

            // Editor has delete:own directly
            expect(rbac.can("editor", "delete", "posts")).toBe(false);
            expect(
                rbac.can("editor", own("delete", userId, ownPostId), "posts"),
            ).toBe(true);
            expect(
                rbac.can("editor", own("delete", userId, otherPostId), "posts"),
            ).toBe(false);
        });
    });

    describe("Permission Explanation with Inheritance", () => {
        it("should correctly explain inherited permissions", () => {
            const rbac = new RBAC(setupRolesWithInheritance());

            // Member inherits read from base
            const explanation = rbac.canExplain("member", "read", "posts");
            expect(explanation).toHaveProperty("granted", true);
            expect(explanation).toHaveProperty("role", "member");
            expect(explanation).toHaveProperty("action", "read");

            // Editor inherits create:own from member
            const editorExplanation = rbac.canExplain(
                "editor",
                "create:own",
                "posts",
            );
            expect(editorExplanation).toHaveProperty("granted", true);
            expect(editorExplanation).toHaveProperty("role", "editor");
            expect(editorExplanation).toHaveProperty("action", "create");
            expect(editorExplanation).toHaveProperty("ownership", "own");
        });

        it("should explain ownership checks with inherited permissions", () => {
            const rbac = new RBAC(setupRolesWithInheritance());
            const userId = "user1";
            const otherPostId = "user2";

            // Editor has delete:own from its own permissions
            const explanation = rbac.canExplain(
                "editor",
                own("delete", userId, otherPostId),
                "posts",
            );

            expect(explanation).toHaveProperty("granted", false);
            expect(explanation).toHaveProperty(
                "reason",
                "OWNERSHIP_CHECK_FAILED",
            );
        });
    });

    describe("Role Updates with Inheritance", () => {
        it("should handle updates to roles with inheritance", () => {
            const rbac = new RBAC(setupRolesWithInheritance());

            // Initially member can't update posts
            expect(rbac.can("member", "update", "posts")).toBe(false);

            // Update member to add update permission
            rbac.updateRoles({
                member: {
                    permissions: {
                        posts: ["create:own", "update:own"],
                    },
                },
            });

            // Now member can update own posts
            expect(rbac.can("member", "update:own", "posts")).toBe(true);

            // Editor should inherit the new permission
            expect(rbac.can("editor", "update:own", "posts")).toBe(true);
        });

        it("should allow adding new inheritance relationships", () => {
            const rbac = new RBAC(setupRolesWithInheritance());

            // Initially moderator can't update categories
            expect(rbac.can("moderator", "update", "categories")).toBe(false);

            // Make moderator inherit from editor
            rbac.updateRoles({
                moderator: {
                    permissions: {
                        comments: ["update", "delete"],
                        posts: ["flag"],
                    },
                    inherits: ["member", "editor"],
                },
            });

            // Now moderator can update categories (inherited from editor)
            expect(rbac.can("moderator", "update", "posts")).toBe(true);
            expect(rbac.can("moderator", "read", "categories")).toBe(true);
        });
    });

    describe("Circular Inheritance Detection", () => {
        it("should handle potential circular inheritance gracefully", () => {
            const rbac = new RBAC({
                role1: {
                    permissions: {
                        resource1: ["action1"],
                        resource2: ["action2"],
                    },
                    inherits: [],
                },
                role2: {
                    permissions: {
                        resource1: ["action1"],
                        resource2: ["action2"],
                    },
                    inherits: ["role1"],
                },
            });

            // Update to create circular reference
            rbac.updateRoles({
                role1: {
                    permissions: {
                        resource1: ["action1"],
                        resource2: ["action2"],
                    },
                    inherits: ["role2"],
                },
            });

            // Should handle circular inheritance without stack overflow
            expect(() =>
                rbac.can("role1", "action1", "resource1"),
            ).not.toThrow();
            expect(() =>
                rbac.can("role2", "action2", "resource2"),
            ).not.toThrow();
        });
    });

    describe("InheritsFrom Method", () => {
        it("should check direct inheritance relationships", () => {
            const rbac = new RBAC(setupRolesWithInheritance());

            // Direct inheritance
            expect(rbac.inheritsFrom("member", "base")).toBe(true);
            expect(rbac.inheritsFrom("editor", "member")).toBe(true);
            expect(rbac.inheritsFrom("admin", "editor")).toBe(true);
            expect(rbac.inheritsFrom("superadmin", "admin")).toBe(true);

            // Non-direct inheritance
            expect(rbac.inheritsFrom("editor", "base")).toBe(true);
            expect(rbac.inheritsFrom("admin", "base")).toBe(true);
            expect(rbac.inheritsFrom("superadmin", "base")).toBe(true);
            expect(rbac.inheritsFrom("superadmin", "editor")).toBe(true);

            // Multiple inheritance paths
            expect(rbac.inheritsFrom("seniorModerator", "moderator")).toBe(
                true,
            );
            expect(rbac.inheritsFrom("seniorModerator", "editor")).toBe(true);
            expect(rbac.inheritsFrom("seniorModerator", "member")).toBe(true);
            expect(rbac.inheritsFrom("seniorModerator", "base")).toBe(true);

            // No inheritance
            expect(rbac.inheritsFrom("moderator", "editor")).toBe(false);
            expect(rbac.inheritsFrom("base", "member")).toBe(false);
            expect(rbac.inheritsFrom("admin", "moderator")).toBe(false);
        });

        it("should handle edge cases", () => {
            const rbac = new RBAC(setupRolesWithInheritance());

            // A role inherits from itself (per our implementation)
            expect(rbac.inheritsFrom("admin", "admin")).toBe(true);

            // Non-existent roles
            expect(rbac.inheritsFrom("nonexistent", "base")).toBe(false);
            expect(rbac.inheritsFrom("admin", "nonexistent")).toBe(false);
            expect(rbac.inheritsFrom("nonexistent", "nonexistent")).toBe(false);
        });

        it("should handle circular inheritance", () => {
            const rbac = new RBAC({
                role1: {
                    permissions: { resource1: ["action1"] },
                    inherits: ["role2"],
                },
                role2: {
                    permissions: { resource2: ["action2"] },
                    inherits: ["role1"],
                },
            });

            // Should handle circular inheritance without stack overflow
            expect(() => rbac.inheritsFrom("role1", "role2")).not.toThrow();

            // Both roles should inherit from each other
            expect(rbac.inheritsFrom("role1", "role2")).toBe(true);
            expect(rbac.inheritsFrom("role2", "role1")).toBe(true);
        });
    });
});
