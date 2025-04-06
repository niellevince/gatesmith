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
- Custom validation functions for complex permission rules
- Permission explanation mechanism to understand why access was granted or denied
- Runtime role configuration updates to modify permissions without restarting

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
4. Custom validation functions
5. Wildcard permissions
6. Role name retrieval
7. Edge cases

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

### Custom Validation Functions

```typescript
import { val } from "./rbac";

// Business hours validation (9 AM to 5 PM, Monday to Friday)
const isBusinessHours = () => {
    const now = new Date();
    const hours = now.getHours();
    const day = now.getDay(); // 0 = Sunday, 1 = Monday, ..., 6 = Saturday
    return day >= 1 && day <= 5 && hours >= 9 && hours < 17;
};

// Only allow report generation during business hours
rbac.can("editor", "reports", val("generate", isBusinessHours));

// Rate limiting example
let reportReadCount = 3; // Pretend user has already read 3 reports today
const isUnderRateLimit = () => {
    return reportReadCount < 5; // Allow max 5 report reads per day
};

// User can read reports if under rate limit
rbac.can("user", "reports", val("read", isUnderRateLimit));

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
rbac.can("admin", "reports", val("export", canExportReports));
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

### Permission Explanations

```typescript
// Get detailed explanation for why a permission was granted or denied
const explanation = rbac.canExplain("admin", "posts", "delete");
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
    "posts",
    own("update", "user1", "user2"),
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
const nonExistent = rbac.canExplain("nonexistent", "posts", "read");
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
    "system",
    "any-action",
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
rbac.can("guest", "posts", "update"); // true

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
rbac.can("developer", "system", "debug"); // true
rbac.getName("developer"); // "Developer"
```

### How the Helper Functions Work

The helper functions perform the comparison immediately and return a permission string with the result:

```typescript
// These helper functions replace the previous string format approach
// Old way:
rbac.can("user", "posts", `update:own|${userId},${resourceId}`);

// New way with helper functions:
rbac.can("user", "posts", own("update", userId, resourceId));
rbac.can("user", "group-chat", group("update", userId, memberIds));
rbac.can(
    "admin",
    "reports",
    val("export", () => complexValidationLogic),
);

// The helper functions evaluate the comparison and return:
// - 'update:own|true' if userId === resourceId
// - 'update:group|true' if userId is in memberIds
// - 'export:val|true' if the validation function returns true
```

## License

ISC
