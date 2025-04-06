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

### Ownership-Based Permissions

```typescript
// Check with ownership (user id and resource owner id)
const userId = "123";
const ownedPostId = "123"; // Post owned by the user
const otherPostId = "456"; // Post owned by someone else

// User can update their own posts
rbac.can("user", "posts", `update:own|${userId},${ownedPostId}`); // true

// User cannot update posts they don't own
rbac.can("user", "posts", `update:own|${userId},${otherPostId}`); // false

// Admin can update any post (no ownership restriction)
rbac.can("admin", "posts", "update"); // true
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

### UI-Friendly Permission Checks

```typescript
// User-friendly permission checks for UI messages
const roleName = rbac.getName("editor");
const canEdit = rbac.can("editor", "posts", `update:own|${userId},${postId}`);

console.log(`${roleName} ${canEdit ? "can" : "cannot"} edit this post.`);
// Output: "Content Editor can edit this post." (if userId matches postId)
```

## License

ISC
