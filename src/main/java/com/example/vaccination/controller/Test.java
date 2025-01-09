package com.example.vaccination.controller;

import com.example.vaccination.model.entity.Employee;
import com.example.vaccination.service.EmployeeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

@Controller
public class Test {
    @Autowired
    EmployeeService employeeService;

    @GetMapping(value = "/hi")
    public String home(Model model) throws ParseException {
        //List<Employee> employees = employeeService.findAll();
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
        Date date = formatter.parse("2002-04-07");
        employeeService.create(new Employee("EM001","here",date,"cuong1@gmail.com","Cuong",true,"EM001.jpg","1","0352312321","admin","admin","tp1",true));
        employeeService.create(new Employee("EM002","here",date,"cuong2@gmail.com","Kuong",true,"EM002.jpg","1","0352315551","admin","a","tp1",true));
        employeeService.create(new Employee("EM003","here",date,"cuong3@gmail.com","Kuong",true,"EM003.jpg","1","0352315552","admin","b","tp1",true));
        employeeService.create(new Employee("EM004","here",date,"cuong4@gmail.com","Kuong",true,"EM004.jpg","1","0352315553","employee","c","tp1",true));
        employeeService.create(new Employee("EM005","here",date,"cuong5@gmail.com","Kuong",true,"EM005.jpg","1","0352315554","employee","d","tp1",true));
        employeeService.create(new Employee("EM006","here",date,"cuong6@gmail.com","Kuong",true,"EM006.jpg","1","0352315555","employee","e","tp1",true));
        employeeService.create(new Employee("EM007","here",date,"cuong7@gmail.com","Kuong",true,"EM007.jpg","1","0352315556","employee","f","tp1",true));

        Employee emp = employeeService.findByEmployeeID("EM002");

        //model.addAttribute("empList", employees);

//        try {
//            AuthResponse authResponse = authService.login(new CheckMsg("admin","12345"));
//            if(authResponse == null) return "error";
//            else return "testUI";
//        } catch (Exception ex) {
//            ex.printStackTrace();
//            throw new ApplicationException();
//        }


//        try {
//            AuthResponse authResponse = authService.login(new CheckMsg("admin","12345"));
//            if(authResponse != null) {
//                Employee emp = employeeService.findByUsername("admin");
             model.addAttribute("emp",emp);
//                return "testUI";
//            }
//        } catch (Exception ex) {
//            ex.printStackTrace();
//            throw new ApplicationException();
//        }
//        return "error";


   // @GetMapping(value = {"/ui","auth/ui"})
   // public String testUi(){
        return "testUI";
    }
}
