# Gatesmith

Crafting elegant access control for modern JavaScript applications

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Gatesmith is a lightweight, flexible permission system that combines the simplicity of RBAC with the power of attribute-based validation. Stop wrestling with complex authorization code and let Gatesmith handle your permission logic with elegance and precision.

## Features

- Class-based API with intuitive methods
- Define hierarchical permissions by role and resource
- Support for ownership-based access control (`create:own`, `update:own`, etc.)
- Dynamic permission checking with ID comparison
- Flexible permission structure that works with any action types
- User-friendly role display names for UI integration
- Wildcard support for granting all permissions on a resource
- Helper functions for immediate ownership and group membership checks
- Custom validation functions for complex permission rules
- Permission explanation mechanism to understand why access was granted or denied
- Runtime role configuration updates to modify permissions without restarting

## Installation

```bash
npm install gatesmith
```

## Quick Start

```typescript
import { RBAC, own, val, WILDCARD_PERMISSION } from "gatesmith";

// Define roles with permissions
const rbac = new RBAC({
    admin: {
        name: "Administrator",
        permissions: {
            posts: ["create", "read", "update", "delete"],
            settings: [WILDCARD_PERMISSION], // Wildcard for all actions
        },
    },
    editor: {
        name: "Content Editor",
        permissions: {
            posts: ["create:own", "read", "update:own", "delete:own"],
        },
    },
    user: {
        name: "Regular User",
        permissions: {
            posts: ["read"],
        },
    },
});

// Basic permission check
rbac.can("admin", "delete", "posts"); // true

// Ownership check
rbac.can("editor", own("update", currentUserId, postOwnerId), "posts"); // true if user owns the post

// Custom validation
rbac.can(
    "admin",
    val("changeApiKeys", () => {
        return isBusinessHours() && hasRequiredTraining();
    }),
    "settings",
);

// Get explanation for permission decision
const explanation = rbac.canExplain(
    "editor",
    own("delete", userId, resourceId),
    "posts",
);
console.log(explanation);
```

## Usage

Build the project:

```bash
npm run build
```

Run the demo:

```bash
npm start
```

Development mode with hot reloading:

```bash
npm run dev
```

## Documentation

### Define Roles & Permissions

```typescript
import { RBAC, RolesConfig, WILDCARD_PERMISSION } from "gatesmith";

// Define role-based permissions with display names
const roles: RolesConfig = {
    admin: {
        name: "Administrator",
        permissions: {
            posts: ["create", "update", "read", "delete"],
            users: ["create", "update", "read", "delete"],
            reports: ["read", "generate", "export:val"], // Custom validation
        },
    },
    superadmin: {
        name: "Super Administrator",
        permissions: {
            // Wildcard permission for all actions on system settings
            system: [WILDCARD_PERMISSION],
            // Specific permissions for other resources
            posts: ["create", "update", "read", "delete"],
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
            "group-chat": ["read", "update:group"],
            reports: ["read:val"], // Custom validation
        },
    },
};

// Create RBAC instance
const rbac = new RBAC(roles);
```

### Basic Permission Checks

```typescript
// Check if role can perform action on resource
rbac.can("admin", "delete", "posts"); // true
rbac.can("user", "read", "posts"); // true
rbac.can("user", "update", "posts"); // false - user can only update:own
```

### Helper Functions for Ownership and Group Checks

```typescript
import { own, group } from "gatesmith";

// User IDs for checking
const userId = "123";
const postOwnerId = "123"; // Post owned by this user
const otherPostId = "456"; // Post owned by someone else
const groupMembers = ["123", "456", "789"]; // User is a member of this group

// Check ownership (returns an evaluated permission string)
rbac.can("user", own("update", userId, postOwnerId), "posts"); // true
rbac.can("user", own("update", userId, otherPostId), "posts"); // false

// Check group membership (returns an evaluated permission string)
rbac.can("user", group("update", userId, groupMembers), "group-chat"); // true
rbac.can("user", group("update", userId, ["456", "789"]), "group-chat"); // false

// Helper functions perform the comparison immediately
// No need to manually compare IDs - the result is already included in the permission
```

### Custom Validation Functions

```typescript
import { val } from "gatesmith";

// Business hours validation (9 AM to 5 PM, Monday to Friday)
const isBusinessHours = () => {
    const now = new Date();
    const hours = now.getHours();
    const day = now.getDay(); // 0 = Sunday, 1 = Monday, ..., 6 = Saturday
    return day >= 1 && day <= 5 && hours >= 9 && hours < 17;
};

// Only allow report generation during business hours
rbac.can("editor", val("generate", isBusinessHours), "reports");

// Rate limiting example
let reportReadCount = 3; // Pretend user has already read 3 reports today
const isUnderRateLimit = () => {
    return reportReadCount < 5; // Allow max 5 report reads per day
};

// User can read reports if under rate limit
rbac.can("user", val("read", isUnderRateLimit), "reports");

// Complex validation combining multiple factors
const canExportReports = () => {
    // You can combine any number of conditions here
    const isAdmin = true;
    const hasExportPermission = true;
    const isDataAvailable = true;
    return (
        isAdmin && hasExportPermission && isDataAvailable && isBusinessHours()
    );
};

// Admin can export reports with complex validation
rbac.can("admin", val("export", canExportReports), "reports");
```

### Wildcard Permissions

```typescript
// Check for wildcard permissions
rbac.hasWildcardPermission("superadmin", "system"); // true

// Wildcard allows any action, even undefined ones
rbac.can("superadmin", "configure-backup", "system"); // true
rbac.can("moderator", "flag-inappropriate", "comments"); // true

// Regular permissions still work normally
rbac.can("moderator", "read", "posts"); // true
rbac.can("moderator", "delete", "posts"); // false - not in permissions list
```

### Permission Pattern Checks with `has()`

```typescript
// Check if a role has a specific permission pattern without evaluating ownership
rbac.has("admin", "update", "posts"); // true
rbac.has("user", "update:own", "posts"); // true
rbac.has("user", "update", "posts"); // false

// Useful for database query optimization
if (rbac.has(userRole, "read:own", "posts")) {
    // User can only read their own posts, add owner filter to query
    const query = { ownerId: userId, ...otherFilters };
    return await postsCollection.find(query);
} else if (rbac.has(userRole, "read", "posts")) {
    // User can read all posts, no owner filter needed
    return await postsCollection.find(otherFilters);
} else {
    // No permission
    return [];
}
```

### Role Management

```typescript
// Get a list of all roles
rbac.getRoles(); // ["admin", "superadmin", "moderator", "editor", "user"]

// Get display names for roles (for UI elements)
rbac.getName("admin"); // "Administrator"
rbac.getName("superadmin"); // "Super Administrator"
rbac.getName("user"); // "Regular User"

// Display names for UI
const availableRoles = rbac.getRoles();
availableRoles.forEach((role) => {
    console.log(`${role}: ${rbac.getName(role)}`);
});
```

### Permission Explanations

```typescript
// Get detailed explanation for why a permission was granted or denied
const explanation = rbac.canExplain("admin", "delete", "posts");
console.log(explanation);
/* Output:
{
  granted: true,
  reason: 'PERMISSION_GRANTED',
  role: 'admin',
  resource: 'posts',
  action: 'delete',
  ownership: undefined,
  details: 'Role "Administrator" has permission to "delete" on resource "posts".'
}
*/

// Explanation for denied permission (ownership check failed)
const denied = rbac.canExplain(
    "user",
    own("update", "user1", "user2"),
    "posts",
);
console.log(denied);
/* Output:
{
  granted: false,
  reason: 'OWNERSHIP_CHECK_FAILED',
  role: 'user',
  resource: 'posts',
  action: 'update',
  ownership: 'own',
  details: 'Role "Regular User" has permission to "update" on resource "posts", but the own check failed.'
}
*/

// Non-existent role explanation
const nonExistent = rbac.canExplain("nonexistent", "read", "posts");
console.log(nonExistent);
/* Output:
{
  granted: false,
  reason: 'ROLE_NOT_FOUND',
  role: 'nonexistent',
  resource: 'posts',
  action: 'read',
  details: 'Role "nonexistent" does not exist.'
}
*/

// Wildcard permission explanation
const wildcardExplanation = rbac.canExplain(
    "superadmin",
    "any-action",
    "system",
);
console.log(wildcardExplanation);
/* Output:
{
  granted: true,
  reason: 'WILDCARD_PERMISSION',
  role: 'superadmin',
  resource: 'system',
  action: 'any-action',
  details: 'Role "Super Administrator" has wildcard permission for resource "system".'
}
*/
```

### Dynamic Role Updates

```typescript
// Update permissions for an existing role at runtime
rbac.updateRoles({
    guest: {
        permissions: {
            posts: ["read", "update"], // Add "update" permission to guest
        },
    },
});

// Check updated permissions
rbac.can("guest", "update", "posts"); // true

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
rbac.getRoles().includes("developer"); // true
rbac.can("developer", "debug", "system"); // true
rbac.getName("developer"); // "Developer"
```

### How the Helper Functions Work

The helper functions perform the comparison immediately and return a permission string with the result:

```typescript
// These helper functions replace the previous string format approach
// Old way:
rbac.can("user", `update:own|${userId},${resourceId}`, "posts");

// New way with helper functions:
rbac.can("user", own("update", userId, resourceId), "posts");
rbac.can("user", group("update", userId, memberIds), "group-chat");
rbac.can(
    "admin",
    val("export", () => complexValidationLogic),
    "reports",
);

// The helper functions evaluate the comparison and return:
// - 'update:own|true' if userId === resourceId
// - 'update:group|true' if userId is in memberIds
// - 'export:val|true' if the validation function returns true
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT
