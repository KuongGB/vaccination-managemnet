package com.example.vaccination.repository;

import com.example.vaccination.model.entity.Employee;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface EmployeeRepository extends JpaRepository<Employee,Integer> {
    @Override
    List<Employee> findAll();

    Employee findByEmployeeID(String id);

    List<Employee> findAllByEmployeeName(String name);

    Employee findByUsername(String username);

    Employee findByPhone(String phone);

    Employee findByEmail(String email);

    List<Employee> findAllByStatusIsTrue();

    @Query(value = "SELECT emp FROM Employee emp WHERE emp.employeeID != :id AND emp.phone = :phone")
    Employee findDuplicatePhone(@Param("id") String id,@Param("phone") String phone);

    @Query(value = "SELECT emp FROM Employee emp WHERE emp.employeeID != :id AND emp.email = :email")
    Employee findDuplicateEmail(@Param("id") String id,@Param("email") String email);
}
