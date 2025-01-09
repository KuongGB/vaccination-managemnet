package com.example.vaccination.controller;

import com.example.vaccination.validator.CustomerValidator;
import com.example.vaccination.model.entity.Customer;
import com.example.vaccination.service.CustomerService;
import jakarta.validation.Valid;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
public class CustomerController {
    @Autowired
    private CustomerService customerService;

    @Autowired
    private CustomerValidator customerValidator;

    @GetMapping("/createCustomer")
    public String createCustomer(Model model) {
        model.addAttribute("customer", new Customer());
        return "createCustomer";
    }

    @PostMapping("/saveCustomer")
    public String saveCustomer(@ModelAttribute("customer") @Valid Customer customer, BindingResult bindingResult) {
        customerValidator.validate(customer, bindingResult);
        if (bindingResult.hasErrors()){
            return "createCustomer";
        }
        String hashedPassword = BCrypt.hashpw(customer.getPassword(), BCrypt.gensalt());
        customer.setPassword(hashedPassword);
        customerService.save(customer);
        return "redirect:/allCustomer";
    }

    @GetMapping("/allCustomer")
    public String allCustomer(Model model) {
        List<Customer> customers = customerService.findAll();
        model.addAttribute("customers", customers);
        return "customerList";
    }

    @PostMapping("/deleteCustomers")
    public String deleteCustomers(@RequestParam(value = "customer", required = false) List<Integer> customerIds) {
        if (customerIds != null) {
            for (int id : customerIds) {
                Customer customer = customerService.findById(id);
                if (customer.getCustomerID() > 0) {
                    customerService.deleteById(id);
                }
            }   //dang test
        }
        return "redirect:/allCustomer";
    }

    @GetMapping("/updateCustomer")
    public String showCustomerUpdateForm(@RequestParam(value = "id") int id, Model model) {
        Customer customer = customerService.findById(id);
        model.addAttribute("customer", customer);
        return "updateCustomer";
    }

    @PostMapping("/updateCustomer")
    public String updateCustomer(@ModelAttribute("customer") @Valid Customer customer, BindingResult bindingResult, Model model){
        customerValidator.validateforUpdate(customer, bindingResult);
        if (bindingResult.hasErrors()){
            return "updateCustomer";
        }
        customerService.save(customer);
        return "redirect:/allCustomer";
    }
}