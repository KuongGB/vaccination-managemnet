package com.example.vaccination.repository;

import com.example.vaccination.model.entity.InjectionResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;

@Repository
public interface InjectionResultRepository extends JpaRepository<InjectionResult,Integer> {

    InjectionResult findByInjectionResultID(int id);

    @Query("SELECT ir FROM InjectionResult ir " +
            "INNER JOIN ir.vaccine_r v " +
            "INNER JOIN v.vaccineType vt " +
            "WHERE (:startDate IS NULL OR ir.injectionDate >= :startDate) " +
            "AND (:endDate IS NULL OR ir.injectionDate <= :endDate)"+
            "AND (:vaccineTypeName IS NULL OR vt.vaccineTypeName Like %:vaccineTypeName%) " +
            "AND (:prevention IS NULL OR ir.prevention Like %:prevention%)")
    List<InjectionResult> findResults(    @Param("startDate") Date startDate,
                                          @Param("endDate") Date endDate,
                                          @Param("vaccineTypeName") String vaccineTypeName,
                                          @Param("prevention") String prevention);

//    Date startDate, Date endDate, String vaccineTypeName, String prevention)
//    @Param("startDate") Date startDate,
//    @Param("endDate") Date endDate,
//    @Param("vaccineTypeName") String vaccineTypeName,
//    @Param("prevention") String prevention);
///-----------------------------------------------------------------------------------------------
//
//    @Query("SELECT ir FROM InjectionResult ir " +
//            "INNER JOIN ir.vaccine_r v " +
//            "INNER JOIN v.vaccineType vt " +
//            "WHERE ir.injectionDate BETWEEN :startDate AND :endDate ")
//    List<InjectionResult> findResultsByInjectionDate(@Param("startDate") Date startDate,
//                                            @Param("endDate") Date endDate);
/////-----------------------------------------------------------------------------------------------
//
//    @Query("SELECT ir FROM InjectionResult ir " +
//            "INNER JOIN ir.vaccine_r v " +
//            "INNER JOIN v.vaccineType vt " +
//            "WHERE vt.vaccineTypeName = :vaccineTypeName")
//    List<InjectionResult> findResultsByVaccineTypeName(@Param("vaccineTypeName") String vaccineTypeName);
/////-----------------------------------------------------------------------------------------------
//
//    @Query("SELECT ir FROM InjectionResult ir WHERE ir.prevention = :prevention")
//    List<InjectionResult> findResultsByPrevention(@Param("prevention") String prevention);
/////-----------------------------------------------------------------------------------------------
//
//    @Query("SELECT ir FROM InjectionResult ir " +
//            "WHERE " +
//            "(:startDate IS NULL OR ir.injectionDate BETWEEN :startDate AND :endDate) " +
//            "AND " +
//            "(:prevention IS NULL OR ir.prevention = :prevention)")
//    List<InjectionResult> findResultsByInjectionDateAndPrevention(@Param("startDate") Date startDate,
//                                                         @Param("endDate") Date endDate,
//                                                         @Param("prevention") String prevention);
/////-----------------------------------------------------------------------------------------------
//
//    @Query("SELECT ir FROM InjectionResult ir " +
//            "INNER JOIN ir.vaccine_r v " +
//            "INNER JOIN v.vaccineType vt " +
//            "WHERE " +
//            "( ir.injectionDate BETWEEN :startDate AND :endDate) " +
//            "AND " +
//            "( vt.vaccineTypeName = :vaccineTypeName)")
//    List<InjectionResult> findResultsByInjectionDateAndVaccineTypeName(@Param("startDate") Date startDate,
//                                                         @Param("endDate") Date endDate,
//                                                         @Param("vaccineTypeName") String vaccineTypeName);
/////---------------------------------------------------------------------------------------------
//    @Query("SELECT ir FROM InjectionResult ir " +
//            "INNER JOIN ir.vaccine_r v " +
//            "INNER JOIN v.vaccineType vt " +
//            "WHERE " +
//            " ir.injectionDate >= :startDate  ")
//    List<InjectionResult> findResultsByStartDate(@Param("startDate") Date startDate);
/////-----------------------------------------------------------------------------------------------
//    @Query("SELECT ir FROM InjectionResult ir " +
//            "INNER JOIN ir.vaccine_r v " +
//            "INNER JOIN v.vaccineType vt " +
//            "WHERE " +
//            " ir.injectionDate <= :endDate  ")
//    List<InjectionResult> findResultsByEndDate(@Param("endDate") Date endDate);
/////-----------------------------------------------------------------------------------------------
//
//    @Query("SELECT ir FROM InjectionResult ir " +
//            "INNER JOIN ir.vaccine_r v " +
//            "INNER JOIN v.vaccineType vt " +
//            "WHERE " +
//            "(:prevention IS NULL OR ir.prevention = :prevention)" +
//            "AND " +
//            "(:vaccineTypeName IS NULL OR vt.vaccineTypeName = :vaccineTypeName)")
//    List<InjectionResult> findResultsByVaccineTypeNameAndPrevention(@Param("prevention") String prevention,
//                                                              @Param("vaccineTypeName") String vaccineTypeName);
/////-----------------------------------------------------------------------------------------------
//
//    @Query("SELECT ir FROM InjectionResult ir " +
//            "WHERE " +
//            "(:startDate IS NULL OR ir.injectionDate >= :startDate) " +
//            "AND " +
//            "(:prevention IS NULL OR ir.prevention = :prevention)")
//   List<InjectionResult> findResultsByStartDateAndPrevention(@Param("startDate") Date startDate,
//                                                             @Param("prevention") String prevention);
/////-----------------------------------------------------------------------------------------------
//
//    @Query("SELECT ir FROM InjectionResult ir " +
//            "INNER JOIN ir.vaccine_r v " +
//            "INNER JOIN v.vaccineType vt " +
//            "WHERE " +
//            "(:startDate IS NULL OR ir.injectionDate >= :startDate)" +
//            "AND " +
//            "(:vaccineTypeName IS NULL OR vt.vaccineTypeName = :vaccineTypeName)")
//    List<InjectionResult> findResultsByStartDateAndVaccineTypeName(@Param("startDate") Date startDate,
//                                                                   @Param("vaccineTypeName") String vaccineTypeName);
//    ///-----------------------------------------------------------------------------------------------
//    @Query("SELECT ir FROM InjectionResult ir " +
//            "INNER JOIN ir.vaccine_r v " +
//            "INNER JOIN v.vaccineType vt " +
//            "WHERE " +
//            "(:startDate IS NULL OR ir.injectionDate >= :startDate)" +
//            "AND " +
//            "(:prevention IS NULL OR ir.prevention = :prevention)"+
//            "AND " +
//            "(:vaccineTypeName IS NULL OR vt.vaccineTypeName = :vaccineTypeName)")
//    List<InjectionResult> findResultsByStartDateAndPreventionAndVaccineTypeName(Date startDate, String prevention, String vaccineTypeName);
//
/////-----------------------------------------------------------------------------------------------
//
//    @Query("SELECT ir FROM InjectionResult ir " +
//            "WHERE " +
//            "(:endDate IS NULL OR ir.injectionDate <= :endDate)" +
//            "AND " +
//            "(:prevention IS NULL OR ir.prevention = :prevention)")
//    List<InjectionResult> findResultsByEndDateAndPrevention(@Param("endDate") Date endDate,
//                                                            @Param("prevention") String prevention);
//
/////-----------------------------------------------------------------------------------------------
//
//    @Query("SELECT ir FROM InjectionResult ir " +
//            "INNER JOIN ir.vaccine_r v " +
//            "INNER JOIN v.vaccineType vt " +
//            "WHERE " +
//            "(:endDate IS NULL OR ir.injectionDate <= :endDate)" +
//            "AND " +
//            "(:vaccineTypeName IS NULL OR vt.vaccineTypeName = :vaccineTypeName)")
//    List<InjectionResult> findResultsByEndDateAndVaccineTypeName(@Param("endDate") Date endDate,
//                                                                 @Param("vaccineTypeName") String vaccineTypeName);
/////-----------------------------------------------------------------------------------------------
//
//    @Query("SELECT ir FROM InjectionResult ir " +
//            "INNER JOIN ir.vaccine_r v " +
//            "INNER JOIN v.vaccineType vt " +
//            "WHERE " +
//            "(:endDate IS NULL OR ir.injectionDate <= :endDate)" +
//            "AND " +
//            "(:vaccineTypeName IS NULL OR vt.vaccineTypeName = :vaccineTypeName)"+
//            "AND " +
//            "(:prevention IS NULL OR ir.prevention = :prevention)")
//    List<InjectionResult> findResultsByEndDateAndPreventionAndVaccineTypeName(@Param("endDate") Date endDate,
//                                                                              @Param("prevention") String prevention,
//                                                                              @Param("vaccineTypeName") String vaccineTypeName);

    ///-----------------------------------------------------------------------------------------------

    //Find data to generate Chart by injectionDate
    @Query(value="SELECT MONTHNAME(ir.injectionDate), SUM(ir.numberOfInjection) AS totalNumberOfInjection FROM InjectionResult ir " +
            "WHERE YEAR(ir.injectionDate) = :yearSelect GROUP BY MONTHNAME(ir.injectionDate)")
    List<String> CountInjectionResult(String yearSelect);


}
