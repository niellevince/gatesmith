/**
 * Simplified Role-Based Access Control (RBAC) System with Ownership
 */

// Types
export type Permission = string; // e.g. 'create', 'read', 'update', 'delete', 'update:own', etc.
export type Resource = string; // e.g. 'posts', 'users', etc.

// Special permission constants
export const WILDCARD_PERMISSION = "*";

export type PermissionAction = string;

// Helper functions for permission checks with immediate evaluation
export function own(
    action: string,
    userId: string,
    resourceOwnerId: string,
): string {
    const isOwner = userId === resourceOwnerId;
    return `${action}:own|${isOwner}`;
}

export function group(
    action: string,
    userId: string,
    groupMemberIds: string[],
): string {
    const isMember = groupMemberIds.includes(userId);
    return `${action}:group|${isMember}`;
}

// Role definitions can be nested (by resource) or flat
export type ResourcePermissions = Record<Resource, Permission[]>;
export type RoleDefinition = ResourcePermissions | Permission[];

export interface RoleConfig {
    name?: string; // Display name for the role
    permissions: ResourcePermissions;
}

export type RolesConfig = Record<string, RoleConfig>;

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

        // Return name if set, otherwise the role name
        return roleConfig.name || roleName;
    }

    /**
     * Checks if a role can perform an action on a resource
     * Simplified syntax: can('user', 'posts', 'update')
     * With helpers: can('user', 'posts', own('update', userId, resourceOwnerId))
     *
     * @param roleName The name of the role
     * @param resource The resource to check
     * @param permission The permission string with optional ownership/group results
     * @returns boolean indicating if the role has the permission
     */
    can(roleName: string, resource: Resource, permission: Permission): boolean {
        // Parse the permission string
        const { action, ownership, comparisonResult } =
            this.parsePermission(permission);

        // Get permissions for the role on the resource
        const permissions = this.getRolePermissions(roleName, resource);

        // Check for wildcard permission first (optimization)
        if (permissions.includes(WILDCARD_PERMISSION)) {
            // If it's a simple wildcard without ownership check, return true immediately
            if (!ownership) {
                return true;
            }

            // For ownership/group checks, we need to check the comparison result
            if (comparisonResult === "true") {
                return true;
            } else if (comparisonResult === "false") {
                return false;
            }
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

        // For pre-evaluated permissions (using helper functions), check the comparison result
        if (ownership && comparisonResult !== undefined) {
            return comparisonResult === "true";
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
     * Format: 'action:ownership|result' or just 'action'
     */
    private parsePermission(permission: string): {
        action: string;
        ownership?: string;
        comparisonResult?: string;
    } {
        // Check if it's a complex permission with results (from helper functions)
        if (permission.includes("|")) {
            // Format: "action:ownership|result" (e.g., "update:own|true" or "update:group|false")
            const [actionPart, resultPart] = permission.split("|");

            if (actionPart.includes(":")) {
                const [action, ownership] = actionPart.split(":");
                return { action, ownership, comparisonResult: resultPart };
            }

            // If no ownership part, return just the action and result
            return { action: actionPart, comparisonResult: resultPart };
        }

        // Check if it's an ownership-qualified permission without result
        if (permission.includes(":")) {
            // Format: "action:ownership" (e.g., "update:own")
            const [action, ownership] = permission.split(":");
            return { action, ownership };
        }

        // Simple permission (e.g., "read")
        return { action: permission };
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

        // If no resource specified or the role definition is a flat array
        if (!resource || Array.isArray(roleDefinition)) {
            return Array.isArray(roleDefinition) ? roleDefinition : [];
        }

        // Get permissions for the specific resource
        return roleDefinition.permissions[resource] || [];
    }
}
