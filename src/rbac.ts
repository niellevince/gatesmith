/**
 * Simplified Role-Based Access Control (RBAC) System with Ownership
 */

// Types
export type Permission = string; // e.g. 'create', 'read', 'update', 'delete', 'update:own', etc.
export type Resource = string; // e.g. 'posts', 'users', etc.

// Special permission constants
export const WILDCARD_PERMISSION = "*";

// Role definitions can be nested (by resource) or flat
export type ResourcePermissions = Record<Resource, Permission[]>;
export type RoleDefinition = ResourcePermissions | Permission[];

export interface RoleConfig {
    name?: string; // Display name for the role
    permissions: RoleDefinition;
}

export type RolesConfig = Record<string, RoleDefinition | RoleConfig>;

/**
 * RBAC Class for role-based permission management
 */
export class RBAC {
    private rolesConfig: RolesConfig;

    constructor(roles: RolesConfig) {
        this.rolesConfig = roles;
    }

    /**
     * Returns an array of all role names in the system
     * @returns string[] Array of role names
     */
    getRoles(): string[] {
        return Object.keys(this.rolesConfig);
    }

    /**
     * Gets the display name for a role
     * @param roleName The internal role name
     * @returns The display name if set, or the role name if not
     */
    getName(roleName: string): string {
        const roleConfig = this.rolesConfig[roleName];

        if (!roleConfig) {
            return roleName;
        }

        // If it's a role config with a name property
        if (
            typeof roleConfig === "object" &&
            !Array.isArray(roleConfig) &&
            "name" in roleConfig
        ) {
            return (roleConfig.name as string) || roleName;
        }

        // Otherwise just return the role name
        return roleName;
    }

    /**
     * Checks if a role can perform an action on a resource
     * Simplified syntax: can('user', 'posts', 'update:own|id1,id2')
     *
     * @param roleName The name of the role
     * @param resource The resource to check
     * @param permission The permission string with optional ownership and IDs
     * @returns boolean indicating if the role has the permission
     */
    can(roleName: string, resource: Resource, permission: Permission): boolean {
        // Parse the permission string
        const { action, ownership, ids } = this.parsePermission(permission);

        // Get permissions for the role on the resource
        const permissions = this.getRolePermissions(roleName, resource);

        // Check for wildcard permission first (optimization)
        if (permissions.includes(WILDCARD_PERMISSION)) {
            // Even with wildcard, we still need to check ownership
            if (!ownership) {
                return true;
            }

            // For ownership checks, continue to ownership validation below
        }

        // Check if any of the role's permissions match the required action
        const hasPermission = permissions.some((p) => {
            // Wildcard permission matches any action
            if (p === WILDCARD_PERMISSION) {
                return true;
            }

            const parsedP = this.parsePermission(p);

            // If actions don't match, not a match
            if (parsedP.action !== action) {
                return false;
            }

            // If required has ownership but granted doesn't, not a match
            if (ownership && !parsedP.ownership) {
                return false;
            }

            // If granted has ownership but required doesn't, it's a match (more specific permission can satisfy a general one)
            if (!ownership && parsedP.ownership) {
                return true;
            }

            // If both have ownership types and they don't match, not a match
            if (
                ownership &&
                parsedP.ownership &&
                ownership !== parsedP.ownership
            ) {
                return false;
            }

            return true;
        });

        if (!hasPermission) {
            return false;
        }

        // If no ownership check needed, return true
        if (!ownership || ownership !== "own" || !ids || ids.length === 0) {
            return true;
        }

        // For ownership checks, when using 'own' with IDs
        if (ids.length >= 2) {
            const currentUserId = ids[0];
            const resourceOwnerId = ids[1];

            return currentUserId === resourceOwnerId;
        }

        return true;
    }

    /**
     * Check if a role has wildcard permissions for a resource
     * @param roleName The name of the role
     * @param resource The resource to check
     * @returns boolean indicating if the role has wildcard permission
     */
    hasWildcardPermission(roleName: string, resource: Resource): boolean {
        const permissions = this.getRolePermissions(roleName, resource);
        return permissions.includes(WILDCARD_PERMISSION);
    }

    /**
     * Private method to parse a permission string into its components
     * Format: 'action:ownership|id1,id2' or just 'action'
     */
    private parsePermission(permission: string): {
        action: string;
        ownership?: string;
        ids?: string[];
    } {
        // Check if permission has ownership context (contains a colon)
        const [action, rest] = permission.split(":");

        if (!rest) {
            return { action };
        }

        // Check if permission has IDs for comparison (contains a pipe)
        const [ownership, idsString] = rest.split("|");

        if (!idsString) {
            return { action, ownership };
        }

        // Parse IDs
        const ids = idsString.split(",").filter(Boolean);

        return { action, ownership, ids };
    }

    /**
     * Private method to get permissions for a role on a specific resource
     */
    private getRolePermissions(
        roleName: string,
        resource?: Resource,
    ): Permission[] {
        // Check if the role exists
        if (!this.rolesConfig[roleName]) {
            return [];
        }

        let roleDefinition = this.rolesConfig[roleName];

        // If it's a role config with permissions property
        if (
            typeof roleDefinition === "object" &&
            !Array.isArray(roleDefinition) &&
            "permissions" in roleDefinition
        ) {
            roleDefinition = roleDefinition.permissions;
        }

        // If no resource specified or the role definition is a flat array
        if (!resource || Array.isArray(roleDefinition)) {
            return Array.isArray(roleDefinition) ? roleDefinition : [];
        }

        // Get permissions for the specific resource
        return (roleDefinition as ResourcePermissions)[resource] || [];
    }
}
