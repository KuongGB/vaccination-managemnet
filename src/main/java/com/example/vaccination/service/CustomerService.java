package com.example.vaccination.service;

import com.example.vaccination.model.entity.Customer;

import com.example.vaccination.model.entity.Customer;
import com.example.vaccination.model.entity.VaccineType;

import java.util.List;
import java.util.Optional;

public interface CustomerService {
    void save(Customer customer);
    List<Customer> findAll();
    Customer findById(int id);
    void deleteById(int id);
}
