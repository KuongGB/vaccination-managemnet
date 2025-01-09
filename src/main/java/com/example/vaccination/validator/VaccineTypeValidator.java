package com.example.vaccination.validator;

import com.example.vaccination.model.entity.VaccineType;
import com.example.vaccination.service.VaccineTypeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
public class VaccineTypeValidator implements Validator {

    @Autowired
    private VaccineTypeService vaccineTypeService;
    @Override
    public boolean supports(Class<?> clazz) {
        return VaccineType.class.equals(clazz);
    }


    @Override
    public void validate(Object target, Errors errors) {
        VaccineType vaccineType = (VaccineType) target;

        if (vaccineTypeService.findByVaccineTypeName(vaccineType.getVaccineTypeName()) != null){
            errors.rejectValue("vaccineTypeName","error.vaccineTypeName","Vaccine Type Name already exists!");
        }

        if (vaccineTypeService.findById(vaccineType.getVaccineTypeID()) != null){
            errors.rejectValue("vaccineTypeID","error.vaccineTypeID","Vaccine Type ID already exists!");
        }
    }
    public void validateUpdate(Object target, Errors errors) {
        VaccineType vaccineType = (VaccineType) target;
        VaccineType  existingVaccineType = vaccineTypeService.findById(vaccineType.getVaccineTypeID());
        if (existingVaccineType != null){
            if (!existingVaccineType.getVaccineTypeName().equals(vaccineType.getVaccineTypeName())){
                if (vaccineTypeService.findByVaccineTypeName(vaccineType.getVaccineTypeName()) != null){
                    errors.rejectValue("vaccineTypeName","error.vaccineTypeName","Vaccine Type Name already exists!");
                }
            }
        }

    }
}
