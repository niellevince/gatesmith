/**
 * Custom RBAC (Role-Based Access Control) System with Ownership
 */

import { RBAC, RolesConfig } from "./rbac";

// Define roles configuration
const roles: RolesConfig = {
    admin: {
        posts: ["create", "update", "read", "delete"],
        users: ["create", "update", "read", "delete"],
        comments: ["create", "update", "read", "delete"],
    },
    editor: {
        posts: ["create", "update", "read", "delete:own"],
        comments: ["create", "update:own", "read", "delete:own"],
    },
    user: {
        posts: ["create:own", "update:own", "read", "delete:own"],
        comments: ["create:own", "update:own", "read", "delete:own"],
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

    // Get all roles
    const availableRoles = rbac.getRoles();
    console.log(`Available roles: [${availableRoles.join(", ")}]`);
    console.log("\n=== Permission Tests ===");

    // Simple permission checks
    logPermissionCheck(
        "Admin can delete posts",
        rbac.can("admin", "posts", "delete"),
        true,
    );

    logPermissionCheck(
        "User can read posts",
        rbac.can("user", "posts", "read"),
        true,
    );

    // Ownership checks
    const userId = "123";
    const postOwnerId = "123"; // Same as user id
    const otherPostOwnerId = "456"; // Different from user id

    console.log("\n=== Ownership Tests ===");

    logPermissionCheck(
        "User can update their own post",
        rbac.can("user", "posts", `update:own|${userId},${postOwnerId}`),
        true,
    );

    logPermissionCheck(
        "User cannot update someone else's post",
        rbac.can("user", "posts", `update:own|${userId},${otherPostOwnerId}`),
        false,
    );

    logPermissionCheck(
        "Admin can update any post (no ownership check)",
        rbac.can("admin", "posts", "update"),
        true,
    );

    logPermissionCheck(
        "Editor can delete their own post",
        rbac.can("editor", "posts", `delete:own|${userId},${postOwnerId}`),
        true,
    );

    logPermissionCheck(
        "Editor cannot delete someone else's post",
        rbac.can("editor", "posts", `delete:own|${userId},${otherPostOwnerId}`),
        false,
    );

    // Additional test cases
    console.log("\n=== Edge Cases ===");

    logPermissionCheck(
        "Non-existent role cannot access anything",
        rbac.can("guest", "posts", "read"),
        false,
    );

    logPermissionCheck(
        "User cannot access non-existent resource",
        rbac.can("user", "nonexistent", "read"),
        false,
    );

    logPermissionCheck(
        "User cannot perform action they don't have permission for",
        rbac.can("user", "posts", "moderate"),
        false,
    );
}

main();
