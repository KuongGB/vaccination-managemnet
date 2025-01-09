package com.example.vaccination.handler;

import com.example.vaccination.model.dto.InjectionResultDto;
import com.example.vaccination.model.entity.InjectionResult;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

@Mapper
public interface ResultMap {
    ResultMap INSTANCE = Mappers.getMapper(ResultMap.class);

    @Mapping(target = "injectionDate", source = "injectionDate")
    @Mapping(target = "nextInjectionDate", source = "nextInjectionDate")
    InjectionResult stringToDate(InjectionResultDto injectionResultDto);
    default Date stringToDate(String dateString) {
        if (dateString == null || dateString == "" || dateString.isEmpty()) {
            return null;
        }

        try {
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
            return dateFormat.parse(dateString);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

}
