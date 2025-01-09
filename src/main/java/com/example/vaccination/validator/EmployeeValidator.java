package com.example.vaccination.validator;


import com.example.vaccination.model.entity.Employee;
import com.example.vaccination.repository.EmployeeRepository;
import com.example.vaccination.service.EmployeeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import java.util.List;

@Component
public class EmployeeValidator implements Validator {
    @Autowired
    private EmployeeService employeeService;

    @Autowired
    private EmployeeRepository employeeRepository;
    @Override
    public boolean supports(Class<?> clazz) {
        return Employee.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        Employee employee = (Employee) target;

        // Kiểm tra logic tùy chỉnh và thêm lỗi vào Errors nếu cần

        if(employee.getEmployeeID().isEmpty())
            errors.rejectValue("employeeID", "error.employeeID", "Must fill this!!");
        else if(!employee.getEmployeeID().matches("^EM[0-9]{1,4}$"))
            errors.rejectValue("employeeID", "error.employeeID", "Form of ID: EMxxxx!!");
        else if(employeeService.isIDExist(employee.getEmployeeID())){
            errors.rejectValue("employeeID", "error.employeeID", "ID exist!!");
        }

        if(employee.getEmail().isEmpty())
            errors.rejectValue("email","error.email","Must fill this!!");
        else if(!employee.getEmail().matches("^[\\w-]+@([\\w-]+\\.)+[\\w-]{2,4}$"))
            errors.rejectValue("email", "error.email", "Wrong format email!!");
        else if(employeeService.isEmailExist(employee.getEmail())){
            errors.rejectValue("email","error.email","Email exist!!");
        }

        if(employee.getPhone().isEmpty())
            errors.rejectValue("phone","error.phone","Must fill this!!");
        else if(!employee.getPhone().matches("^[0][1-9]\\d{7,9}$"))
            errors.rejectValue("phone","error.phone", "Phone form: 0xxxxxxxxxx!!");
        else if(employeeService.isPhoneExist(employee.getPhone())){
            errors.rejectValue("phone","error.phone","Phone number exist!!");
        }

        if(employee.getUsername().isEmpty())
            errors.rejectValue("username","error.username","Must fill this!!");
        else if(!employee.getUsername().matches("^([a-zA-Z0-9]*\\S)$"))
            errors.rejectValue("username", "error.username", "Non-whitespace please!!");
        else if(employeeService.isUsernameExist(employee.getUsername())){
            errors.rejectValue("username","error.username","Username exist!!");
        }

        if(employee.getEmployeeName().isEmpty())
            errors.rejectValue("employeeName","error.employeeName","Must fill this!!");
        else if(!employee.getEmployeeName().matches("^([a-zA-Z]*\\s*)*$"))
            errors.rejectValue("employeeName", "error.employeeName", "Only characters!!");

        if(employee.getAddress().isEmpty())
            errors.rejectValue("address","error.address","Must fill this!!");

        if(employee.getPassword().isEmpty())
            errors.rejectValue("password","error.password","Must fill this!!");

        if(employee.getDateOfBirth() == null)
            errors.rejectValue("dateOfBirth","error.dateOfBirth","Must fill this!!");

        if(employee.getPosition().equals("0"))
            errors.rejectValue("position","error.position","Choose position!!");
    }

    public void validateForUpdate(Object target, Errors errors) {
        Employee employee = (Employee) target;

        // Kiểm tra logic tùy chỉnh và thêm lỗi vào Errors nếu cần

        if(employee.getEmail().isEmpty())
            errors.rejectValue("email","error.email","Must fill this!!");
        else if(!employee.getEmail().matches("^[\\w-]+@([\\w-]+\\.)+[\\w-]{2,4}$"))
            errors.rejectValue("email", "error.email", "Wrong format email!!");

        if(employee.getPhone().isEmpty())
            errors.rejectValue("phone","error.phone","Must fill this!!");
        else if(!employee.getPhone().matches("^[0][1-9]\\d{7,9}$"))
            errors.rejectValue("phone","error.phone", "Phone form: 0xxxxxxxxxx!!");

        if(employee.getEmployeeName().isEmpty())
            errors.rejectValue("employeeName","error.employeeName","Must fill this!!");
        else if(!employee.getEmployeeName().matches("^([a-zA-Z]*\\s*)*$"))
            errors.rejectValue("employeeName", "error.employeeName", "Only characters!!");

        if(employee.getAddress().isEmpty())
            errors.rejectValue("address","error.address","Must fill this!!");

        if(employee.getDateOfBirth() == null || employee.getDateOfBirth().equals(""))
            errors.rejectValue("dateOfBirth","error.dateOfBirth","Must fill this!!");

        Employee oldEmp = employeeRepository.findByEmployeeID(employee.getEmployeeID());
        List<Employee> employeeList = employeeRepository.findAll();
        for(Employee emp : employeeList){
            if(emp != oldEmp){
                if(emp.getEmail().equals(employee.getEmail())){
                    errors.rejectValue("email","error.email","Email exist!!");
                }

                if(emp.getPhone().equals(employee.getPhone())){
                    errors.rejectValue("phone","error.phone","Phone number exist!!");
                }
            }
        }
    }
}
