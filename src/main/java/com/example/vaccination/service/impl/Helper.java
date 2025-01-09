package com.example.vaccination.service.impl;

import com.example.vaccination.model.entity.Vaccine;
import com.example.vaccination.model.entity.VaccineType;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

@Service
public class Helper {

    @Autowired
    private VaccineServiceImpl vaccineService;

    @Autowired
    private VaccineTypeServiceImpl vaccineTypeService;

    public boolean checkExcelFormat(MultipartFile file) {
        String contentType = file.getContentType();
        if (contentType.equals("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")) {
            return true;
        } else {
            return false;
        }
    }

    public List<Vaccine> convertExcelToListOfProduct(InputStream is) throws Exception {
        List<Vaccine> list = new ArrayList<>();
        List<Vaccine> vaccineList = vaccineService.getAllVaccine();
        XSSFWorkbook workbook = new XSSFWorkbook(is);
        XSSFSheet sheet = workbook.getSheet("data");
        int rowNumber = 0;
        Iterator<Row> iterator = sheet.iterator();
        while (iterator.hasNext()) {
            Row row = iterator.next();
            if (rowNumber == 0) {
                rowNumber++;
                continue;
            }
            Iterator<Cell> cells = row.iterator();
            int cid = 0;
            Vaccine vaccine = new Vaccine();
            while (cells.hasNext()) {
                Cell cell = cells.next();
                switch (cid) {
                    case 0:
                        String tmp1 = "" + (int)cell.getNumericCellValue();
                        for (Vaccine check :vaccineList) {
                            if (tmp1.equals(check.getVaccineID())){
                                throw new Exception("Vaccine Code already exists in list: " + tmp1);
                            }
                        }
                        for (Vaccine item :list) {
                            if (tmp1.equals(item.getVaccineID())){
                                throw new Exception("Vaccine Code already exists: " + tmp1);
                            }
                        }
                        vaccine.setVaccineID(tmp1);
                        break;
                    case 1:
                        String tmp2 = cell.getStringCellValue();
                        for (Vaccine check :vaccineList) {
                            if (tmp2.equals(check.getVaccineName())){
                                throw new Exception("Vaccine Name already exists in list: " + tmp2);
                            }
                        }
                        for (Vaccine item :list) {
                            if (tmp2.equals(item.getVaccineName())){
                                throw new Exception("Vaccine Name already exists: " + tmp2);
                            }
                        }
                        vaccine.setVaccineName(tmp2);
                        break;
                    case 2:
                        vaccine.setOrigin( cell.getStringCellValue());
                        break;
                    case 3:
                        vaccine.setTimeBeginNextInjection(cell.getDateCellValue());
                        break;
                    case 4:
                        vaccine.setTimeEndNextInjection(cell.getDateCellValue());
                        break;
                    case 5:
                        vaccine.setIndication(cell.getStringCellValue());
                        break;
                    case 6:
                        vaccine.setContraindication(cell.getStringCellValue());
                        break;
                    case 7:
                        vaccine.setNumberOfInjection("" + (int)cell.getNumericCellValue());
                        break;
                    case 8:
                        vaccine.setStatus(cell.getBooleanCellValue());
                        break;
                    case 9:
                        vaccine.setDescription(cell.getStringCellValue());
                        break;
                    case 10:
                        String tmp = cell.getStringCellValue();
                        List<VaccineType> vaccineType = vaccineTypeService.findAll();
                        boolean check = false;
                        for (VaccineType existingVaccineTypes :vaccineType) {
                            if (existingVaccineTypes.getVaccineTypeID().equals(tmp)){
                                vaccine.setVaccineType(existingVaccineTypes);
                                check = true;
                                break;
                            }
                        }
                        if (!check){
                            throw new Exception("Vaccine Type doesn't not exist: " + tmp);
                        }
                        break;
                    default:
                        break;
                }
                cid++;
            }
            list.add(vaccine);
        }
        return list;
    }
}
