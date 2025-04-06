/**
 * Custom RBAC (Role-Based Access Control) System with Ownership
 */

import { RBAC, RolesConfig, WILDCARD_PERMISSION, own, group } from "./rbac";

// Define roles configuration with display names and wildcards
const roles: RolesConfig = {
    admin: {
        name: "Administrator",
        permissions: {
            posts: ["create", "update", "read", "delete"],
            users: ["create", "update", "read", "delete"],
            comments: ["create", "update", "read", "delete"],
            "group-chat": ["create", "update", "read", "delete", "moderate"],
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
            "group-chat": [WILDCARD_PERMISSION],
        },
    },
    editor: {
        name: "Content Editor",
        permissions: {
            posts: ["create:own", "update:own", "read", "delete:own"],
            comments: ["create:own", "update:own", "read", "delete:own"],
            "group-chat": ["read", "update:group"],
        },
    },
    moderator: {
        name: "Content Moderator",
        permissions: {
            // Wildcard for all comment actions
            comments: [WILDCARD_PERMISSION],
            // Limited permissions on posts
            posts: ["read", "update"],
            // Group chat moderation
            "group-chat": ["read", "moderate"],
        },
    },
    user: {
        name: "Regular User",
        permissions: {
            posts: ["create:own", "update:own", "read", "delete:own"],
            comments: ["create:own", "update:own", "read", "delete:own"],
            "group-chat": ["read", "update:group"],
        },
    },
    guest: {
        name: "Guest User",
        permissions: {
            posts: ["read"],
            comments: ["read"],
            "group-chat": ["read"],
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
console.log("RBAC Demonstration:");
console.log("------------------");

// Basic permission tests
console.log("\n1. Basic Permissions:");
console.log(
    "Administrator can delete posts:",
    rbac.can("admin", "posts", "delete"),
);
console.log("Regular User can read posts:", rbac.can("user", "posts", "read"));

// Ownership tests with the new helper functions
console.log("\n2. Ownership Tests:");
const user1Id = "user1";
const user2Id = "user2";
const adminId = "admin1";

// User can update their own posts
console.log(
    "User can update their own post:",
    rbac.can("user", "posts", own("update", user1Id, user1Id)),
);

// User cannot update others' posts
console.log(
    "User cannot update another user's post:",
    rbac.can("user", "posts", own("update", user1Id, user2Id)),
);

// Admin can update any post
console.log("Admin can update any post:", rbac.can("admin", "posts", "update"));

// Editor can delete their own posts
console.log(
    "Editor can delete their own post:",
    rbac.can("editor", "posts", own("delete", user1Id, user1Id)),
);

// Group membership tests
console.log("\n3. Group Membership Tests:");
const groupMembers = ["user1", "user3", "user5"];
const nonGroupMembers = ["user2", "user4"];

// User in the group can update the group chat
console.log(
    "User can update group chat they're a member of:",
    rbac.can("user", "group-chat", group("update", user1Id, groupMembers)),
);

// User not in the group cannot update
console.log(
    "User cannot update group chat they're not a member of:",
    rbac.can("user", "group-chat", group("update", user2Id, groupMembers)),
);

// Moderator can moderate any group chat
console.log(
    "Moderator can moderate any group chat:",
    rbac.can("moderator", "group-chat", "moderate"),
);

// Wildcard permission tests
console.log("\n4. Wildcard Permission Tests:");
console.log(
    "Super Admin has wildcard permission for system:",
    rbac.hasWildcardPermission("superadmin", "system"),
);

console.log(
    "Super Admin can do any action on users (even undefined actions):",
    rbac.can("superadmin", "users", "some-undefined-action"),
);

console.log(
    "Moderator has wildcard permission for comments:",
    rbac.hasWildcardPermission("moderator", "comments"),
);

// Role name tests
console.log("\n5. Role Names:");
console.log("'superadmin' display name:", rbac.getName("superadmin"));
console.log("'moderator' display name:", rbac.getName("moderator"));
console.log("'guest' display name:", rbac.getName("guest"));
console.log(
    "'manager' display name (undefined role):",
    rbac.getName("manager"),
);

// Edge case tests
console.log("\n6. Edge Cases:");
console.log(
    "Check permission for nonexistent role:",
    rbac.can("nonexistent", "posts", "read"),
);
console.log("Guest can read posts:", rbac.can("guest", "posts", "read"));
console.log("Guest cannot update posts:", rbac.can("guest", "posts", "update"));
