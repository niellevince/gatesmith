/**
 * Custom RBAC (Role-Based Access Control) System with Ownership
 */

import { RBAC, RolesConfig, WILDCARD_PERMISSION } from "./rbac";

// Define roles configuration with display names and wildcards
const roles: RolesConfig = {
    admin: {
        name: "Administrator",
        permissions: {
            posts: ["create", "update", "read", "delete"],
            users: ["create", "update", "read", "delete"],
            comments: ["create", "update", "read", "delete"],
        },
    },
    superadmin: {
        name: "Super Administrator",
        permissions: {
            // Wildcard permission for all actions on system settings
            system: [WILDCARD_PERMISSION],
            // Wildcard permission for all actions on all resources
            posts: [WILDCARD_PERMISSION],
            users: [WILDCARD_PERMISSION],
            comments: [WILDCARD_PERMISSION],
        },
    },
    editor: {
        name: "Content Editor",
        permissions: {
            posts: ["create", "update", "read", "delete:own"],
            comments: ["create", "update:own", "read", "delete:own"],
        },
    },
    moderator: {
        name: "Content Moderator",
        permissions: {
            // Wildcard for all comment actions
            comments: [WILDCARD_PERMISSION],
            // Limited permissions on posts
            posts: ["read", "update"],
        },
    },
    user: {
        name: "Regular User",
        permissions: {
            posts: ["create:own", "update:own", "read", "delete:own"],
            comments: ["create:own", "update:own", "read", "delete:own"],
        },
    },
    guest: {
        name: "Guest User",
        permissions: {
            posts: ["read"],
            comments: ["read"],
        },
    },
};

/**
 * Helper function for better logging
 */
function logPermissionCheck(
    description: string,
    result: boolean,
    expected: boolean,
) {
    const status = result === expected ? "✅" : "❌";
    console.log(`${status} ${description}: ${result}, expected=${expected}`);
}

// Create RBAC instance
const rbac = new RBAC(roles);

// Example usage
function main() {
    console.log("=== RBAC System Demonstration ===");
    console.log("RBAC instance created with the following roles:");

    // Get all roles with their display names
    const availableRoles = rbac.getRoles();
    console.log("Available roles:");
    availableRoles.forEach((role) => {
        console.log(`- ${role}: "${rbac.getName(role)}"`);
    });

    console.log("\n=== Basic Permission Tests ===");

    // Simple permission checks
    logPermissionCheck(
        `${rbac.getName("admin")} can delete posts`,
        rbac.can("admin", "posts", "delete"),
        true,
    );

    logPermissionCheck(
        `${rbac.getName("user")} can read posts`,
        rbac.can("user", "posts", "read"),
        true,
    );

    // Ownership checks
    const userId = "123";
    const postOwnerId = "123"; // Same as user id
    const otherPostOwnerId = "456"; // Different from user id

    console.log("\n=== Ownership Tests ===");

    logPermissionCheck(
        `${rbac.getName("user")} can update their own post`,
        rbac.can("user", "posts", `update:own|${userId},${postOwnerId}`),
        true,
    );

    logPermissionCheck(
        `${rbac.getName("user")} cannot update someone else's post`,
        rbac.can("user", "posts", `update:own|${userId},${otherPostOwnerId}`),
        false,
    );

    logPermissionCheck(
        `${rbac.getName("admin")} can update any post (no ownership check)`,
        rbac.can("admin", "posts", "update"),
        true,
    );

    logPermissionCheck(
        `${rbac.getName("editor")} can delete their own post`,
        rbac.can("editor", "posts", `delete:own|${userId},${postOwnerId}`),
        true,
    );

    logPermissionCheck(
        `${rbac.getName("editor")} cannot delete someone else's post`,
        rbac.can("editor", "posts", `delete:own|${userId},${otherPostOwnerId}`),
        false,
    );

    // Wildcard permission tests
    console.log("\n=== Wildcard Permission Tests ===");

    // Test superadmin with wildcard permissions
    logPermissionCheck(
        `${rbac.getName("superadmin")} has wildcard permission for system`,
        rbac.hasWildcardPermission("superadmin", "system"),
        true,
    );

    logPermissionCheck(
        `${rbac.getName("superadmin")} can perform unknown action on system due to wildcard`,
        rbac.can("superadmin", "system", "configure-backup"),
        true,
    );

    logPermissionCheck(
        `${rbac.getName("superadmin")} can perform any action on users due to wildcard`,
        rbac.can("superadmin", "users", "ban"),
        true,
    );

    // Test moderator with wildcard for comments
    logPermissionCheck(
        `${rbac.getName("moderator")} has wildcard permission for comments`,
        rbac.hasWildcardPermission("moderator", "comments"),
        true,
    );

    logPermissionCheck(
        `${rbac.getName("moderator")} can perform unknown action on comments due to wildcard`,
        rbac.can("moderator", "comments", "flag-inappropriate"),
        true,
    );

    logPermissionCheck(
        `${rbac.getName("moderator")} can perform only specific actions on posts (no wildcard)`,
        rbac.can("moderator", "posts", "delete"),
        false,
    );

    // Additional test cases
    console.log("\n=== Edge Cases ===");

    logPermissionCheck(
        "Non-existent role cannot access anything",
        rbac.can("unknown-role", "posts", "read"),
        false,
    );

    logPermissionCheck(
        `${rbac.getName("guest")} can read posts`,
        rbac.can("guest", "posts", "read"),
        true,
    );

    logPermissionCheck(
        `${rbac.getName("guest")} cannot update posts`,
        rbac.can("guest", "posts", "update"),
        false,
    );

    // Test getName fallback for non-existent role
    console.log("\n=== Role Name Tests ===");
    console.log(`Role name for 'admin': "${rbac.getName("admin")}"`);
    console.log(`Role name for 'superadmin': "${rbac.getName("superadmin")}"`);
    console.log(`Role name for 'moderator': "${rbac.getName("moderator")}"`);
    console.log(`Role name for 'guest': "${rbac.getName("guest")}"`);
    console.log(
        `Role name for non-existent role 'manager': "${rbac.getName("manager")}"`,
    );
}

main();
