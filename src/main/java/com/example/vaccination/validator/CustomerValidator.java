package com.example.vaccination.validator;

import com.example.vaccination.model.entity.Customer;
import com.example.vaccination.service.impl.CustomerServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import java.util.List;

@Component
public class CustomerValidator implements Validator {

    @Autowired
    private CustomerServiceImpl customerService;

    @Override
    public boolean supports(Class<?> clazz) {
        return false;
    }

    @Override
    public void validate(Object target, Errors errors) {
        Customer customer =(Customer) target;
        List<Customer> list = customerService.findAll();
        for (Customer ctp :list) {
            if(ctp.getIndentifyCard().equals(customer.getIndentifyCard())){
                errors.rejectValue("indentifyCard", "error.indentifyCard","Identify card already exists");
            }
            if(ctp.getUsername().equals(customer.getUsername())){
                errors.rejectValue("username", "error.username","Username already exists");
            }
            if(ctp.getEmail().equals(customer.getEmail())){
                errors.rejectValue("email", "error.email","Email already exists");
            }
            if (ctp.getPhone().equals(customer.getPhone())){
                errors.rejectValue("phone", "error.phone","Phone number already exists");
            }
            if(!customer.getEmail().matches("^[\\w-]+@([\\w-]+\\.)+[\\w-]{2,4}$") && !customer.getEmail().isEmpty()){
                errors.rejectValue("email", "error.email","Email has the wrong format");
            }
            if (!customer.getPhone().matches("^[0-9]+$") && !customer.getPhone().isEmpty()){
                errors.rejectValue("phone", "error.phone","Phone number contains invalid characters");
            }
        }
    }

    public void validateforUpdate(Object target, Errors errors) {
        Customer customer =(Customer) target;
        List<Customer> list = customerService.findAll();
        Customer existtingCustomer = customerService.findById(customer.getCustomerID());
        for (Customer ctp :list) {
            if(existtingCustomer != null && !existtingCustomer.getIndentifyCard().equals(customer.getIndentifyCard()) && ctp.getIndentifyCard().equals(customer.getIndentifyCard())){
                errors.rejectValue("indentifyCard", "error.indentifyCard","Identify card already exists");
            }
            if(existtingCustomer != null && !existtingCustomer.getUsername().equals(customer.getUsername()) && ctp.getUsername().equals(customer.getUsername())){
                errors.rejectValue("username", "error.username","Username already exists");
            }
            if(existtingCustomer != null && !existtingCustomer.getEmail().equals(customer.getEmail()) && ctp.getEmail().equals(customer.getEmail())){
                errors.rejectValue("email", "error.email","Email already exists");
            }
            if (existtingCustomer != null && !existtingCustomer.getPhone().equals(customer.getPhone()) && ctp.getPhone().equals(customer.getPhone())){
                errors.rejectValue("phone", "error.phone","Phone number already exists");
            }
            if(!customer.getEmail().matches("^[\\w-]+@([\\w-]+\\.)+[\\w-]{2,4}$") && !customer.getEmail().isEmpty()){
                errors.rejectValue("email", "error.email","Email has the wrong format");
            }
            if (!customer.getPhone().matches("^[0-9]+$") && !customer.getPhone().isEmpty()){
                errors.rejectValue("phone", "error.phone","Phone number contains invalid characters");
            }
        }
    }
}