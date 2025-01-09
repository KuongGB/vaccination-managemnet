package com.example.vaccination.security;

import com.example.vaccination.model.entity.Employee;
import com.example.vaccination.service.EmployeeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private EmployeeService employeeService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Kiểm tra xem user có tồn tại trong CSDL không?
        Employee employee = employeeService.findByUsername(username);
        if (employee == null) {
           throw new UsernameNotFoundException("User Not Found!");
        }

        UserSecurity userSecurity = new UserSecurity(employee);
        return userSecurity;
    }

}