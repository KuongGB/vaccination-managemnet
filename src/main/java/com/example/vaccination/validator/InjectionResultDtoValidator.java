package com.example.vaccination.validator;

import com.example.vaccination.model.dto.InjectionResultDto;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
public class InjectionResultDtoValidator implements Validator {
    @Override
    public boolean supports(Class<?> clazz) {
        return InjectionResultDto.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        InjectionResultDto injectionResultDto = (InjectionResultDto) target;
        Integer numberOfInjection = (injectionResultDto.getNumberOfInjection() == 0 )? null : (injectionResultDto.getNumberOfInjection());


        /*injectionScheduleDto.getPlace() == null ||*/
        if (injectionResultDto.getInjectionDate().trim().isEmpty() && injectionResultDto.getNextInjectionDate().trim().isEmpty() &&  injectionResultDto.getInjectionPlace().trim().isEmpty() && injectionResultDto.getVaccine_r().getVaccineID().trim().isEmpty()
              && injectionResultDto.getNumberOfInjection() == 0  && injectionResultDto.getPrevention().trim().isEmpty() && injectionResultDto.getCustomer().getCustomerID() == 0) {
//|| injectionResultDto.getNumberOfInjection() == 0
            // Cả ba trường đều là null, tạo lỗi riêng rẽ cho mỗi trường
            errors.rejectValue("injectionDate", "NotNull.injectionResultDto.injectionDate", "From date is not null!!!");
            errors.rejectValue("nextInjectionDate", "NotNull.injectionResultDto.nextInjectionDate", "To date is not null!!!");
            errors.rejectValue("injectionPlace", "NotNull.injectionResultDto.injectionPlace", "Place is not null!!!");
            errors.rejectValue("vaccine_r","NotNull.injectionResultDto.vaccine_r","Choose a vaccine!!!");
            errors.rejectValue("customer","NotNull.injectionResultDto.customer","Choose a customer!!!");
            errors.rejectValue("prevention","NotNull.injectionResultDto.prevention","Prevention not null!!!");
            errors.rejectValue("numberOfInjection","NotNull.injectionResultDto.numberOfInjection","Number of injection not null!!!");

        }else {

            // Kiểm tra nếu endDate là null
            if (injectionResultDto.getNextInjectionDate().trim().isEmpty()) {
                errors.rejectValue("nextInjectionDate", "NotNull.injectionResultDto.nextInjectionDate", "To date is not null!!!");
            }

            // Kiểm tra nếu startDate là null
            if (injectionResultDto.getInjectionDate().trim().isEmpty()) {
                errors.rejectValue("injectionDate", "NotNull.injectionResultDto.injectionDate", "From date is not null!!!");
            }



            if (injectionResultDto.getVaccine_r().getVaccineID().trim().isEmpty()) {
                errors.rejectValue("vaccine_r","NotNull.injectionResultDto.vaccine_r","Choose a vaccine!!!");
            }

            // Kiểm tra nếu place là null hoặc chuỗi rỗng
            if (injectionResultDto.getInjectionPlace() == null || injectionResultDto.getInjectionPlace().trim().isEmpty()) {
                errors.rejectValue("injectionPlace", "NotNull.injectionResultDto.injectionPlace", "Place is not null!!!");
            }
            if (injectionResultDto.getCustomer().getCustomerID() ==0 ) {
                errors.rejectValue("customer","NotNull.injectionResultDto.customer","Choose a customer!!!");
            }
            if (injectionResultDto.getPrevention().trim().isEmpty()) {
                errors.rejectValue("prevention","NotNull.injectionResultDto.prevention","Prevention is not null!!!");
            }
//            if ( injectionResultDto.getNumberOfInjection() instanceof  ) {
//                errors.rejectValue("numberOfInjection","NotNull.injectionResultDto.numberOfInjection","Choose a number!!!");
//            }

            if ( injectionResultDto.getNumberOfInjection() == 0 ) {
                errors.rejectValue("numberOfInjection","NotNull.injectionResultDto.numberOfInjection","Choose a number!!!");
            }

            if ( numberOfInjection == null ) {
                errors.rejectValue("numberOfInjection","NotNull.injectionResultDto.numberOfInjection","Choose a number!!!");
            }










        }


    }


}
