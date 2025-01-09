package com.example.vaccination.security;

import com.example.vaccination.model.entity.Employee;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class UserSecurity implements UserDetails {

    private Employee employee;

    public UserSecurity(Employee employee) {
        this.employee = employee;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + employee.getPosition().toUpperCase()));

        List<String> permissionList = new ArrayList<>();
        permissionList.add("admin".toUpperCase());
        permissionList.add("employee".toUpperCase());
        if (permissionList != null) {
            for (String permission : permissionList) {
                authorities.add(new SimpleGrantedAuthority(permission.toUpperCase()));
            }
        }
        return authorities;
    }

    @Override
    public String getUsername() {
        return employee.getUsername();
    }

    @Override
    public String getPassword() {
        return employee.getPassword();
    }

    @Override
    public boolean isAccountNonExpired() {
        return employee.isStatus();
    }

    @Override
    public boolean isAccountNonLocked() {
        return employee.isStatus();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return employee.isStatus();
    }

    @Override
    public boolean isEnabled() {
        return employee.isStatus();
    }

    public Employee getEmployee() {
        return employee;
    }
}