package com.example.vaccination.validator;

import com.example.vaccination.model.dto.InjectionScheduleDto;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
public class InjectionScheduleDtoValidator implements Validator {
    @Override
    public boolean supports(Class<?> clazz) {
        return InjectionScheduleDto.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        InjectionScheduleDto injectionScheduleDto = (InjectionScheduleDto) target;

        /*injectionScheduleDto.getPlace() == null ||*/
        if (injectionScheduleDto.getStartDate().trim().isEmpty() && injectionScheduleDto.getEndDate().trim().isEmpty() &&  injectionScheduleDto.getPlace().trim().isEmpty() && injectionScheduleDto.getVaccine_s().getVaccineID().trim().isEmpty()) {
            // Cả ba trường đều là null, tạo lỗi riêng rẽ cho mỗi trường
            errors.rejectValue("startDate", "NotNull.injectionScheduleDto.startDate", "From date is not null!!!");
            errors.rejectValue("endDate", "NotNull.injectionScheduleDto.endDate", "To date is not null!!!");
            errors.rejectValue("place", "NotEmpty.injectionScheduleDto.place", "Place is not null!!!");
            errors.rejectValue("vaccine_s","NotEmpty.injectionScheduleDto.vaccine_s","Choose a vaccine!!!");
        }else{
            // Kiểm tra nếu endDate là null
            if (injectionScheduleDto.getEndDate().trim().isEmpty()) {
                errors.rejectValue("endDate", "NotNull.injectionScheduleDto.endDate", "To date is not null!!!");
            }
            // Kiểm tra nếu startDate là null
            if (injectionScheduleDto.getStartDate().trim().isEmpty()) {
                errors.rejectValue("startDate", "NotNull.injectionScheduleDto.startDate", "From date is not null!!!");
            }
            if (injectionScheduleDto.getVaccine_s().getVaccineID().trim().isEmpty()) {
                errors.rejectValue("vaccine_s","NotEmpty.injectionScheduleDto.vaccine_s","Choose a vaccine!!!");
            }
            // Kiểm tra nếu place là null hoặc chuỗi rỗng
            if (injectionScheduleDto.getPlace() == null || injectionScheduleDto.getPlace().trim().isEmpty()) {
                errors.rejectValue("place", "NotEmpty.injectionScheduleDto.place", "Place is not null!!!");
            }

        }
    }
}
