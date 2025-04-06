# Custom RBAC (Role-Based Access Control) System

A lightweight and flexible role-based access control system implemented in TypeScript, with support for resource-specific permissions and ownership checking.

## Features

- Class-based API with intuitive methods
- Define hierarchical permissions by role and resource
- Support for ownership-based access control (`create:own`, `update:own`, etc.)
- Dynamic permission checking with ID comparison
- Flexible permission structure that works with any action types
- User-friendly role display names for UI integration
- Wildcard support for granting all permissions on a resource
- Helper functions for immediate ownership and group membership checks

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/custom_rbac.git
cd custom_rbac
```

Install dependencies:

```bash
npm install
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

## Testing

The project includes a comprehensive set of test cases demonstrating various aspects of the RBAC system:

1. Basic permission checks
2. Ownership-based permissions using helper functions
3. Group membership checks
4. Wildcard permissions
5. Role name retrieval
6. Edge cases

To run the demonstration:

```bash
npm start
```

## Examples

### Define Roles & Permissions

```typescript
import { RBAC, RolesConfig, WILDCARD_PERMISSION } from "./rbac";

// Define role-based permissions with display names
const roles: RolesConfig = {
    admin: {
        name: "Administrator",
        permissions: {
            posts: ["create", "update", "read", "delete"],
            users: ["create", "update", "read", "delete"],
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
        },
    },
};

// Create RBAC instance
const rbac = new RBAC(roles);
```

### Basic Permission Checks

```typescript
// Check if role can perform action on resource
rbac.can("admin", "posts", "delete"); // true
rbac.can("user", "posts", "read"); // true
rbac.can("user", "posts", "update"); // false - user can only update:own
```

### Helper Functions for Ownership and Group Checks

```typescript
import { own, group } from "./rbac";

// User IDs for checking
const userId = "123";
const postOwnerId = "123"; // Post owned by this user
const otherPostId = "456"; // Post owned by someone else
const groupMembers = ["123", "456", "789"]; // User is a member of this group

// Check ownership (returns an evaluated permission string)
rbac.can("user", "posts", own("update", userId, postOwnerId)); // true
rbac.can("user", "posts", own("update", userId, otherPostId)); // false

// Check group membership (returns an evaluated permission string)
rbac.can("user", "group-chat", group("update", userId, groupMembers)); // true
rbac.can("user", "group-chat", group("update", userId, ["456", "789"])); // false

// Helper functions perform the comparison immediately
// No need to manually compare IDs - the result is already included in the permission
```

### Wildcard Permissions

```typescript
// Check for wildcard permissions
rbac.hasWildcardPermission("superadmin", "system"); // true

// Wildcard allows any action, even undefined ones
rbac.can("superadmin", "system", "configure-backup"); // true
rbac.can("moderator", "comments", "flag-inappropriate"); // true

// Regular permissions still work normally
rbac.can("moderator", "posts", "read"); // true
rbac.can("moderator", "posts", "delete"); // false - not in permissions list
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

### How the Helper Functions Work

The helper functions perform the ID comparison immediately and return a permission string with the result:

```typescript
// These helper functions replace the previous string format approach
// Old way:
rbac.can("user", "posts", `update:own|${userId},${resourceId}`);

// New way with helper functions:
rbac.can("user", "posts", own("update", userId, resourceId));

// The helper functions evaluate the comparison and return:
// - 'update:own|true' if userId === resourceId
// - 'update:own|false' if userId !== resourceId

// Group membership checks work similarly:
rbac.can("user", "chat", group("update", userId, memberIds));
// Returns 'update:group|true' if userId is in memberIds, otherwise 'update:group|false'
```

## License

ISC
