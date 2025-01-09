package com.example.vaccination.service.impl;

import com.example.vaccination.model.entity.Customer;
import com.example.vaccination.model.entity.VaccineType;
import com.example.vaccination.repository.CustomerRepository;
import com.example.vaccination.service.CustomerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class CustomerServiceImpl implements CustomerService {
    @Autowired
    private CustomerRepository customerRepository;

    @Override
    public void save(Customer customer) {
        customerRepository.save(customer);
    }

    @Override
    public List<Customer> findAll() {
        return customerRepository.findAll();
    }

    @Override
    public Customer findById(int id) {
        Optional<Customer> result = customerRepository.findById(id);
        Customer customer = null;
        if (result.isPresent()) {
            customer = result.get();
        }
        else {
            throw new RuntimeException("Did not find customer id - " + id);
        }
        return customer;
    }

    @Override
    public void deleteById(int id) {
        customerRepository.deleteById(id);
    }

}