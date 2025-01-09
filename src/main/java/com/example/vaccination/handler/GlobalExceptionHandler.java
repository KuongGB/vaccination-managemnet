package com.example.vaccination.handler;

import com.example.vaccination.exception.NotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ModelAndView handleException(Exception ex) {
        ModelAndView modelAndView = new ModelAndView("error");
        modelAndView.addObject("errorMessage", "An error occurred: " + ex.getMessage());
        return modelAndView;
    }

    @ExceptionHandler(NotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ModelAndView handleNotFoundException(NotFoundException ex) {
        ModelAndView modelAndView = new ModelAndView("page404");
        modelAndView.addObject("errorMessage", "An error occurred: " + ex.getMessage());
        return modelAndView;
    }

    @ExceptionHandler({IOException.class, java.sql.SQLException.class})
    public ModelAndView handleIOException(Exception ex) {
        ModelAndView model = new ModelAndView("error");
        model.addObject("errorMessage", ex.getMessage());
        return model;
    }
    @ExceptionHandler(IllegalStateException.class)
    public ModelAndView handleIllegalStateException(IllegalStateException ex) {
        ModelAndView modelAndView = new ModelAndView("error");
        modelAndView.addObject("errorMessage", "An error occurred: " + ex.getMessage());
        return modelAndView;
    }

}