package com.example.vaccination.handler;

import com.example.vaccination.model.dto.InjectionScheduleDto;
import com.example.vaccination.model.entity.InjectionSchedule;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

@Mapper
public interface ScheduleMap {
    /*@Mapping(target = "startDate", source = "injectionSchedule.startDate")
    @Mapping(target = "endDate", source = "injectionSchedule.endDate")
    InjectionScheduleDto injectionScheduleToInjectionScheduleDto(InjectionSchedule injectionSchedule);
    List<InjectionScheduleDto> injectionSchedulesToInjectionScheduleDtos(List<InjectionSchedule> injectionSchedules);*/

    ScheduleMap INSTANCE = Mappers.getMapper(ScheduleMap.class);

    @Mapping(target = "startDate", source = "startDate")
    @Mapping(target = "endDate", source = "endDate")
    InjectionSchedule stringToDate(InjectionScheduleDto injectionScheduleDto);
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
