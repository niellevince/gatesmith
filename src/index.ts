/**
 * Gatesmith - Crafting elegant access control for modern JavaScript applications
 */

import {
    RBAC,
    RolesConfig,
    WILDCARD_PERMISSION,
    own,
    group,
    val,
} from "./rbac";

// Define roles configuration with display names and wildcards
const roles: RolesConfig = {
    admin: {
        name: "Administrator",
        permissions: {
            posts: ["create", "update", "update:own", "read", "delete"],
            users: ["create", "update", "read", "delete"],
            comments: ["create", "update", "read", "delete"],
            "group-chat": ["create", "update", "read", "delete", "moderate"],
            reports: ["read", "generate", "export:val"],
        },
        description: "System administrator with full access to most resources",
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
            reports: [WILDCARD_PERMISSION],
        },
        description: "Super administrator with complete system access",
    },
    editor: {
        name: "Content Editor",
        permissions: {
            posts: ["create:own", "update:own", "read", "delete:own"],
            comments: ["create:own", "update:own", "read", "delete:own"],
            "group-chat": ["read", "update:group"],
            reports: ["read", "generate:val"],
        },
        description: "Content editor with management of own content",
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
        description: "Moderator for community content",
    },
    user: {
        name: "Regular User",
        permissions: {
            posts: ["create:own", "update:own", "read", "delete:own"],
            comments: ["create:own", "update:own", "read", "delete:own"],
            "group-chat": ["read", "update:group"],
            reports: ["read:val"],
            users: ["read:own"],
        },
        description: "Standard user account",
    },
    guest: {
        name: "Guest User",
        permissions: {
            posts: ["read"],
            comments: ["read"],
            "group-chat": ["read"],
        },
        description: "Unauthenticated guest with limited access",
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
    rbac.can("admin", "delete", "posts"),
);
console.log("Regular User can read posts:", rbac.can("user", "read", "posts"));

// Ownership tests with the new helper functions
console.log("\n2. Ownership Tests:");
const user1Id = "user1";
const user2Id = "user2";
const adminId = "admin1";

// User can update their own posts
console.log(
    "User can update their own post:",
    rbac.can("user", own("update", user1Id, user1Id), "posts"),
);

// User cannot update others' posts
console.log(
    "User cannot update another user's post:",
    rbac.can("user", own("update", user1Id, user2Id), "posts"),
);

// Admin can update any post
console.log("Admin can update any post:", rbac.can("admin", "update", "posts"));

// Editor can delete their own posts
console.log(
    "Editor can delete their own post:",
    rbac.can("editor", own("delete", user1Id, user1Id), "posts"),
);

// Group membership tests
console.log("\n3. Group Membership Tests:");
const groupMembers = ["user1", "user3", "user5"];
const nonGroupMembers = ["user2", "user4"];

// User in the group can update the group chat
console.log(
    "User can update group chat they're a member of:",
    rbac.can("user", group("update", user1Id, groupMembers), "group-chat"),
);

// User not in the group cannot update
console.log(
    "User cannot update group chat they're not a member of:",
    rbac.can("user", group("update", user2Id, groupMembers), "group-chat"),
);

// Moderator can moderate any group chat
console.log(
    "Moderator can moderate any group chat:",
    rbac.can("moderator", "moderate", "group-chat"),
);

// Custom validation tests
console.log("\n4. Custom Validation Tests:");

// Business hours validation (9 AM to 5 PM, Monday to Friday)
const isBusinessHours = () => {
    const now = new Date();
    const hours = now.getHours();
    const day = now.getDay(); // 0 = Sunday, 1 = Monday, ..., 6 = Saturday
    return day >= 1 && day <= 5 && hours >= 9 && hours < 17;
};

// Check if we're in business hours for report generation
console.log(
    "Editor can generate reports during business hours:",
    rbac.can("editor", val("generate", isBusinessHours), "reports"),
);

// Rate limiting example (allow 5 report reads per day)
let reportReadCount = 3; // Pretend user has already read 3 reports today
const isUnderRateLimit = () => {
    return reportReadCount < 5;
};

// User can read reports if under rate limit
console.log(
    "User can read reports if under rate limit:",
    rbac.can("user", val("read", isUnderRateLimit), "reports"),
);

// Simulate reaching the rate limit
reportReadCount = 5;
console.log(
    "User cannot read reports if rate limit reached:",
    rbac.can("user", val("read", isUnderRateLimit), "reports"),
);

// Permission explanation tests
console.log("\n5. Permission Explanation Tests:");

// Explain why a permission is granted
const explanation1 = rbac.canExplain("admin", "delete", "posts");
console.log("Explanation for admin deleting posts:");
console.log(explanation1);

// Explain why a permission is denied (ownership check failed)
const explanation2 = rbac.canExplain(
    "user",
    own("update", user1Id, user2Id),
    "posts",
);
console.log("\nExplanation for user updating another user's post:");
console.log(explanation2);

// Explain for non-existent role
const explanation3 = rbac.canExplain("nonexistent", "read", "posts");
console.log("\nExplanation for non-existent role:");
console.log(explanation3);

// Explanation for wildcard permission
const explanation4 = rbac.canExplain("superadmin", "any-action", "system");
console.log("\nExplanation for superadmin with wildcard permission:");
console.log(explanation4);

// Role update tests
console.log("\n6. Role Update Tests:");

// Current permissions
console.log(
    "Before update - Guest can update posts:",
    rbac.can("guest", "update", "posts"),
);

// Update roles by adding new permissions to an existing role
rbac.updateRoles({
    guest: {
        permissions: {
            posts: ["read", "update"], // Add "update" permission
        },
    },
});

// Check updated permissions
console.log(
    "After update - Guest can update posts:",
    rbac.can("guest", "update", "posts"),
);

// Add a completely new role
rbac.updateRoles({
    developer: {
        name: "Developer",
        permissions: {
            system: ["read", "debug"],
            logs: ["read", "download"],
        },
        description: "Technical developer with system access",
    },
});

// Check if the new role exists and has permissions
console.log("Developer role exists:", rbac.getRoles().includes("developer"));
console.log(
    "Developer can debug system:",
    rbac.can("developer", "debug", "system"),
);

// Wildcard permission tests
console.log("\n7. Wildcard Permission Tests:");
console.log(
    "Super Admin has wildcard permission for system:",
    rbac.hasWildcardPermission("superadmin", "system"),
);

console.log(
    "Super Admin can do any action on users (even undefined actions):",
    rbac.can("superadmin", "some-undefined-action", "users"),
);

console.log(
    "Moderator has wildcard permission for comments:",
    rbac.hasWildcardPermission("moderator", "comments"),
);

// Role name tests
console.log("\n8. Role Names:");
console.log("'superadmin' display name:", rbac.getName("superadmin"));
console.log("'moderator' display name:", rbac.getName("moderator"));
console.log("'guest' display name:", rbac.getName("guest"));
console.log("'developer' display name (new role):", rbac.getName("developer"));
console.log(
    "'manager' display name (undefined role):",
    rbac.getName("manager"),
);

// Edge case tests
console.log("\n9. Edge Cases:");
console.log(
    "Check permission for nonexistent role:",
    rbac.can("nonexistent-role", "read", "posts"),
);
console.log("Guest can read posts:", rbac.can("guest", "read", "posts"));
// After the update, guest can update posts
console.log(
    "Guest can update posts (after update):",
    rbac.can("guest", "update", "posts"),
);

// Add a new section for permission array tests
console.log("\n10. Permission Array Tests:");

// Check if user can either read or update their own post
console.log(
    "User can either read OR update their own post:",
    rbac.can("user", ["read", own("update", user1Id, user1Id)], "posts"),
);

// Check if user can either delete someone else's post or update their own (should pass)
console.log(
    "User can either delete another's post OR update their own:",
    rbac.can(
        "user",
        [own("delete", user1Id, user2Id), own("update", user1Id, user1Id)],
        "posts",
    ),
);

// Check if user can either update or delete someone else's post (should fail)
console.log(
    "User can either update OR delete another's post (should fail):",
    rbac.can(
        "user",
        [own("update", user1Id, user2Id), own("delete", user1Id, user2Id)],
        "posts",
    ),
);

// Example with explanation for an array of permissions
console.log("\n11. Explanation for Permission Arrays:");
const arrayExplanation = rbac.canExplain(
    "user",
    ["read", own("update", user1Id, user2Id), own("delete", user1Id, user1Id)],
    "posts",
);
console.log("Explanation for array of permissions:");
console.log(arrayExplanation);

// Add to the Permission Array Tests section
console.log("\nAdministrator permissions with arrays:");
// Admin can either update any post or update their own post (should pass with general update)
console.log(
    "Admin can update any post OR update own post:",
    rbac.can("admin", ["update", own("update", adminId, user2Id)], "posts"),
);

// Admin can update their own post specifically (should also pass)
console.log(
    "Admin can update their own post specifically:",
    rbac.can("admin", own("update", adminId, adminId), "posts"),
);

// Explanation for admin permissions
const adminExplanation = rbac.canExplain(
    "admin",
    ["update", own("update", adminId, user2Id)],
    "posts",
);
console.log("Explanation for admin permissions array:");
console.log(adminExplanation);

// Replace the Administrator permissions section with a cleaner example
console.log("\n12. Administrator 'update' and 'update:own' Permissions:");

// Show that admin can update any post (general update permission)
console.log("Admin can update any post:", rbac.can("admin", "update", "posts"));

// Show that admin can update their own post (specific ownership permission)
console.log(
    "Admin can update their own post:",
    rbac.can("admin", own("update", adminId, adminId), "posts"),
);

// Show that admin can update another user's post (general permission applies)
console.log(
    "Admin can update another user's post:",
    rbac.can("admin", own("update", adminId, user2Id), "posts"),
);

// Show that admin passes with array of either permission
console.log(
    "Admin can update OR update-own (array check):",
    rbac.can("admin", ["update", own("update", adminId, adminId)], "posts"),
);

// Compare to regular user who needs specific ownership
console.log(
    "Regular user can update ONLY their own posts (not any post):",
    !rbac.can("user", "update", "posts") &&
        rbac.can("user", own("update", user1Id, user1Id), "posts") &&
        !rbac.can("user", own("update", user1Id, user2Id), "posts"),
);

// Show explanation for admin permissions
const adminUpdateExplanation = rbac.canExplain(
    "admin",
    ["update", own("update", adminId, adminId)],
    "posts",
);
console.log("\nExplanation for admin update permissions array:");
console.log(adminUpdateExplanation);