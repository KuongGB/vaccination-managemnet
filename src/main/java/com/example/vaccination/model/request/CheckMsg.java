package com.example.vaccination.model.request;

import com.example.vaccination.model.entity.Employee;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CheckMsg {
    private Employee emp;
    private String msg;
}