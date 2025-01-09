package com.example.vaccination.controller;

import com.example.vaccination.service.EmployeeService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class AuthController {
    @Autowired
    private EmployeeService employeeService;


//    @PostMapping("/login")
//    public String login(HttpSession session, @ModelAttribute("loginrequest") CheckMsg request, Model model) {
//        try {
//            AuthResponse authResponse = authService.login(request);
//            Employee emp = employeeService.findByUsername(request.getUsername());
//
////            List<Employee> employees = new ArrayList<>();
////            employees = employeeService.findAll();
//            if(authResponse != null){
//                //session.setAttribute("fullname", emp.getEmployeeName());
//                model.addAttribute("emp",emp.getEmployeeName());
//                return "homePage";
//            }
//        } catch (Exception ex) {
//            ex.printStackTrace();
//            throw new ApplicationException();
//        }
//        return "error";
//    }
    @GetMapping(value = {"/login"})
    public String loginPage(Model model) {return "login";}

    @GetMapping(value = "/logout")
    public String logoutPage(Model model, HttpServletRequest request, HttpServletResponse response) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null) {
                new SecurityContextLogoutHandler().logout(request, response, auth);
                request.getSession().invalidate();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return loginPage(model);
    }
}