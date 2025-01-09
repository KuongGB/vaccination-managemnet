package com.example.vaccination.service;

import com.example.vaccination.model.entity.VaccineType;

import java.util.List;

public interface VaccineTypeService {
    List<VaccineType> findAll();
    VaccineType save(VaccineType vaccineType);

    VaccineType findById(String id);
    VaccineType findByVaccineTypeName(String name);
    List<VaccineType> findAllByStatus();
}
