package com.example.vaccination.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Collection;

@Controller
public class HomeController {

    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_EMPLOYEE')")
    @GetMapping(value = {"/", "/home"})
    public String showHomepage(Model model) {
        return "homePage";
    }
    @GetMapping(value = {"/access-denied"})
    public String accessDenied(Model model) {
        return "access-denied";
    }

}