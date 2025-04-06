# Custom RBAC (Role-Based Access Control) System

A lightweight and flexible role-based access control system implemented in TypeScript, with support for resource-specific permissions and ownership checking.

## Features

- Class-based API with intuitive methods
- Define hierarchical permissions by role and resource
- Support for ownership-based access control (`create:own`, `update:own`, etc.)
- Dynamic permission checking with ID comparison
- Flexible permission structure that works with any action types

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
import { RBAC, RolesConfig } from "./rbac";

// Define role-based permissions
const roles: RolesConfig = {
    admin: {
        posts: ["create", "update", "read", "delete"],
        users: ["create", "update", "read", "delete"],
    },
    editor: {
        posts: ["create", "update", "read", "delete:own"],
        comments: ["create", "update:own", "read", "delete:own"],
    },
    user: {
        posts: ["create:own", "update:own", "read", "delete:own"],
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

### Get Available Roles

```typescript
// Get a list of all roles
rbac.getRoles(); // ["admin", "editor", "user"]
```

## License

ISC
