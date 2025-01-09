package com.example.vaccination.repository;

import com.example.vaccination.model.entity.VaccineType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface VaccineTypeRepository extends JpaRepository<VaccineType ,String > {
    Optional <VaccineType> findById(String Id);

    Optional <VaccineType> findByVaccineTypeName(String name);

    List<VaccineType> findAll();

    List<VaccineType> findAllByStatus(boolean status);
}
