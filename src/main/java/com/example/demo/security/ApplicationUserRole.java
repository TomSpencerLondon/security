package com.example.demo.security;

import static com.example.demo.security.ApplicationUserPermission.*;

import com.google.common.collect.Sets;
import java.util.Set;

public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(COURSE_READ));


    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }
}
