/**
 * Simplified Role-Based Access Control (RBAC) System with Ownership
 */

// Types
export type Permission = string; // e.g. 'create', 'read', 'update', 'delete', 'update:own', etc.
export type Resource = string; // e.g. 'posts', 'users', etc.

// Special permission constants
export const WILDCARD_PERMISSION = "*";

export type PermissionAction = string;
export type ValidatorFunction = () => boolean; // Custom validator function type

// Result type for permission explanation
export interface PermissionExplanation {
    granted: boolean;
    reason: string;
    role: string;
    resource: string;
    action: string;
    ownership?: string;
    details?: string;
}

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

/**
 * Helper function for custom validation
 * @param action The action to check
 * @param validator A function that returns true or false based on custom logic
 * @returns A permission string with result of validation
 */
export function val(action: string, validator: ValidatorFunction): string {
    const isValid = validator();
    return `${action}:val|${isValid}`;
}

// Role definitions can be nested (by resource) or flat
export type ResourcePermissions = Record<Resource, Permission[]>;
export type RoleDefinition = ResourcePermissions | Permission[];

export interface RoleConfig {
    name?: string; // Display name for the role
    permissions: ResourcePermissions;
    description?: string; // Optional description of the role
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
     * Updates the roles configuration at runtime
     * @param newRoles New roles configuration or partial update
     * @param merge Whether to merge with existing roles (default: true)
     * @returns Updated RBAC instance (for method chaining)
     */
    updateRoles(newRoles: RolesConfig, merge: boolean = true): RBAC {
        if (merge) {
            // Merge new roles with existing ones
            this.rolesConfig = {
                ...this.rolesConfig,
                ...newRoles,
            };

            // Deep merge permissions for roles that exist in both
            for (const roleName in newRoles) {
                if (
                    this.rolesConfig[roleName] &&
                    this.rolesConfig[roleName].permissions &&
                    newRoles[roleName].permissions
                ) {
                    // Preserve existing role properties like name if not provided in new config
                    if (
                        !newRoles[roleName].name &&
                        this.rolesConfig[roleName].name
                    ) {
                        newRoles[roleName].name =
                            this.rolesConfig[roleName].name;
                    }

                    // Merge permissions for existing resources
                    for (const resource in this.rolesConfig[roleName]
                        .permissions) {
                        if (newRoles[roleName].permissions[resource]) {
                            // If resource exists in both, combine the permissions (avoiding duplicates)
                            const existingPermissions =
                                this.rolesConfig[roleName].permissions[
                                    resource
                                ];
                            const newPermissions =
                                newRoles[roleName].permissions[resource];

                            newRoles[roleName].permissions[resource] = [
                                ...new Set([
                                    ...existingPermissions,
                                    ...newPermissions,
                                ]),
                            ];
                        } else {
                            // Preserve existing resources not in the new config
                            newRoles[roleName].permissions[resource] = [
                                ...this.rolesConfig[roleName].permissions[
                                    resource
                                ],
                            ];
                        }
                    }
                }
            }
        }

        // Replace existing roles with new ones
        this.rolesConfig = merge ? this.rolesConfig : newRoles;
        return this;
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
     * Simplified syntax: can('user', 'update', 'posts')
     * With helpers:
     *   can('user', own('update', userId, resourceOwnerId), 'posts')
     *   can('user', group('update', userId, groupMemberIds), 'posts')
     *   can('user', val('update', () => customLogic), 'posts')
     * Array syntax:
     *   can('user', ['update', own('update', userId, resourceOwnerId)], 'posts')
     *
     * @param roleName The name of the role
     * @param permission The permission string with optional ownership/group/validation results, or an array of permissions
     * @param resource The resource to check
     * @returns boolean indicating if the role has the permission
     */
    can(
        roleName: string,
        permission: Permission | Permission[],
        resource: Resource,
    ): boolean {
        // Convert single permission to array for consistent handling
        const permissions = Array.isArray(permission)
            ? permission
            : [permission];

        // Return true if any of the permissions are granted
        return permissions.some((perm) =>
            this.checkSinglePermission(roleName, perm, resource),
        );
    }

    /**
     * Checks a single permission for a role on a resource
     * @param roleName The name of the role
     * @param permission The permission string
     * @param resource The resource to check
     * @returns boolean indicating if the role has the permission
     * @private Internal method used by can()
     */
    private checkSinglePermission(
        roleName: string,
        permission: Permission,
        resource: Resource,
    ): boolean {
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

            // For ownership/group/validation checks with pipe, check the comparison result
            if (comparisonResult !== undefined) {
                return comparisonResult === "true";
            }

            // If ownership is specified without a pipe, treat it as true
            return true;
        }

        // Check if the role has the general permission (without ownership)
        // This allows "update" permission to satisfy "update:own" check regardless of ownership
        if (ownership && permissions.includes(action)) {
            // If the role has the general permission, it can perform ownership-specific actions
            // regardless of the ownership check (because general permission means "can do anything")
            return true;
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

            // If we're checking a general permission (e.g., "read")
            // but the role only has specific permissions (e.g., "read:own"),
            // then it's not a match
            if (!ownership && parsedP.ownership) {
                return false;
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

        // For pre-evaluated permissions with pipe (e.g., from own()), check the comparison result
        if (comparisonResult !== undefined) {
            return comparisonResult === "true";
        }

        // If ownership is specified without a pipe (e.g., 'action:own'), treat it as true
        return true;
    }

    /**
     * Explains why a permission check would pass or fail
     * @param roleName The name of the role
     * @param permission The permission string with optional ownership/group/validation results, or an array of permissions
     * @param resource The resource to check
     * @returns An explanation object with details about the permission decision
     */
    canExplain(
        roleName: string,
        permission: Permission | Permission[],
        resource: Resource,
    ): PermissionExplanation | PermissionExplanation[] {
        // If it's an array of permissions, return an array of explanations
        if (Array.isArray(permission)) {
            return permission.map((perm) =>
                this.explainSinglePermission(roleName, perm, resource),
            );
        }

        // For a single permission, return a single explanation
        return this.explainSinglePermission(roleName, permission, resource);
    }

    /**
     * Explains why a single permission check would pass or fail
     * @param roleName The name of the role
     * @param permission The permission string
     * @param resource The resource to check
     * @returns An explanation object with details about the permission decision
     * @private Internal method used by canExplain()
     */
    private explainSinglePermission(
        roleName: string,
        permission: Permission,
        resource: Resource,
    ): PermissionExplanation {
        // Check if the role exists
        if (!this.rolesConfig[roleName]) {
            return {
                granted: false,
                reason: "ROLE_NOT_FOUND",
                role: roleName,
                resource,
                action: permission,
                details: `Role "${roleName}" does not exist.`,
            };
        }

        // Parse the permission string
        const { action, ownership, comparisonResult } =
            this.parsePermission(permission);

        // Get permissions for the role on the resource
        const permissions = this.getRolePermissions(roleName, resource);

        // Check if the resource exists for this role
        if (permissions.length === 0) {
            return {
                granted: false,
                reason: "RESOURCE_NOT_ALLOWED",
                role: roleName,
                resource,
                action,
                ownership,
                details: `Role "${this.getName(roleName)}" does not have access to resource "${resource}".`,
            };
        }

        // Check for wildcard permission
        if (permissions.includes(WILDCARD_PERMISSION)) {
            // If it's a simple wildcard without ownership check, permission is granted
            if (!ownership) {
                return {
                    granted: true,
                    reason: "WILDCARD_PERMISSION",
                    role: roleName,
                    resource,
                    action,
                    details: `Role "${this.getName(roleName)}" has wildcard permission for resource "${resource}".`,
                };
            }

            // For ownership checks with pipe, check the comparison result
            if (comparisonResult !== undefined) {
                if (comparisonResult === "true") {
                    return {
                        granted: true,
                        reason: "WILDCARD_WITH_OWNERSHIP",
                        role: roleName,
                        resource,
                        action,
                        ownership,
                        details: `Role "${this.getName(roleName)}" has wildcard permission for resource "${resource}" and ownership check passed.`,
                    };
                } else {
                    return {
                        granted: false,
                        reason: "OWNERSHIP_CHECK_FAILED",
                        role: roleName,
                        resource,
                        action,
                        ownership,
                        details: `Role "${this.getName(roleName)}" has wildcard permission for resource "${resource}", but the ${ownership} check failed.`,
                    };
                }
            }

            // If ownership is specified without pipe, treat it as granted
            return {
                granted: true,
                reason: "WILDCARD_WITH_OWNERSHIP_DEFAULT",
                role: roleName,
                resource,
                action,
                ownership,
                details: `Role "${this.getName(roleName)}" has wildcard permission for resource "${resource}" and default ownership is assumed to be granted.`,
            };
        }

        // Check if the role has general permission (without ownership)
        if (ownership && permissions.includes(action)) {
            return {
                granted: true,
                reason: "GENERIC_PERMISSION_WITH_OWNERSHIP",
                role: roleName,
                resource,
                action,
                ownership,
                details: `Role "${this.getName(roleName)}" has generic "${action}" permission for resource "${resource}", which allows ${ownership} operations regardless of ownership.`,
            };
        }

        // Check if the role has the specific permission
        const matchingPermissions = permissions.filter((p) => {
            const parsedP = this.parsePermission(p);

            // Simple action match (without ownership)
            if (parsedP.action === action && !parsedP.ownership && !ownership) {
                return true;
            }

            // Exact match with ownership
            if (parsedP.action === action && parsedP.ownership === ownership) {
                return true;
            }

            return false;
        });

        if (matchingPermissions.length === 0) {
            // Check if we have any ownership-qualified permissions for this action
            const hasOwnershipPermissions = permissions.some((p) => {
                const parsedP = this.parsePermission(p);
                return parsedP.action === action && parsedP.ownership;
            });

            if (!ownership && hasOwnershipPermissions) {
                return {
                    granted: false,
                    reason: "REQUIRES_OWNERSHIP",
                    role: roleName,
                    resource,
                    action,
                    ownership,
                    details: `Role "${this.getName(roleName)}" has ownership-restricted permission for "${action}" on resource "${resource}". You must specify ownership.`,
                };
            }

            return {
                granted: false,
                reason: "ACTION_NOT_ALLOWED",
                role: roleName,
                resource,
                action,
                ownership,
                details: `Role "${this.getName(roleName)}" does not have permission to "${action}" on resource "${resource}"${
                    ownership ? ` with ${ownership} ownership` : ""
                }.`,
            };
        }

        // If we have a matching permission with pipe, check the comparison result
        if (ownership && comparisonResult !== undefined) {
            if (comparisonResult === "true") {
                return {
                    granted: true,
                    reason: "PERMISSION_WITH_OWNERSHIP",
                    role: roleName,
                    resource,
                    action,
                    ownership,
                    details: `Role "${this.getName(roleName)}" can "${action}" on resource "${resource}" with ${ownership} ownership.`,
                };
            } else {
                return {
                    granted: false,
                    reason: "OWNERSHIP_CHECK_FAILED",
                    role: roleName,
                    resource,
                    action,
                    ownership,
                    details: `Role "${this.getName(roleName)}" has permission to "${action}" on resource "${resource}", but the ${ownership} check failed.`,
                };
            }
        }

        // For permissions with ownership but without pipe, it's always granted
        if (ownership) {
            return {
                granted: true,
                reason: "PERMISSION_WITH_OWNERSHIP_DEFAULT",
                role: roleName,
                resource,
                action,
                ownership,
                details: `Role "${this.getName(roleName)}" has permission to "${action}" on resource "${resource}" with ${ownership} ownership (default granted).`,
            };
        }

        // Simple permission granted
        return {
            granted: true,
            reason: "PERMISSION_GRANTED",
            role: roleName,
            resource,
            action,
            ownership,
            details: `Role "${this.getName(roleName)}" has permission to "${action}" on resource "${resource}"${
                ownership ? ` with ${ownership} ownership` : ""
            }.`,
        };
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

        const roleDefinition = this.rolesConfig[roleName];

        // If no resource specified or the role definition is a flat array
        if (!resource || Array.isArray(roleDefinition)) {
            return Array.isArray(roleDefinition) ? roleDefinition : [];
        }

        // Get permissions for the specific resource
        return roleDefinition.permissions[resource] || [];
    }
}
