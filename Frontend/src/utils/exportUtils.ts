import jsPDF from 'jspdf';
import * as XLSX from 'xlsx';
import { AttendanceRecord, Student } from '../types';
import { format } from 'date-fns';

export const exportToPDF = (data: AttendanceRecord[], students: Student[]) => {
  const pdf = new jsPDF();
  
  pdf.setFontSize(18);
  pdf.text('Attendance Report', 20, 20);
  
  pdf.setFontSize(12);
  let yPosition = 40;
  
  data.forEach((record, index) => {
    if (yPosition > 280) {
      pdf.addPage();
      yPosition = 20;
    }
    
    const student = students.find(s => s.studentId === record.studentId);
    const studentName = student ? student.name : record.studentId;
    const date = format(new Date(record.date), 'PPP');
    
    pdf.text(`${index + 1}. ${studentName} - ${date} - ${record.attendancePercentage}%`, 20, yPosition);
    yPosition += 10;
  });
  
  pdf.save('attendance-report.pdf');
};

export const exportToExcel = (data: AttendanceRecord[], students: Student[]) => {
  const exportData = data.map(record => {
    const student = students.find(s => s.studentId === record.studentId);
    return {
      'Student ID': record.studentId,
      'Student Name': student ? student.name : 'Unknown',
      'Date': format(new Date(record.date), 'PP'),
      'Check In': record.checkIn ? format(new Date(record.checkIn), 'pp') : 'Not marked',
      'Check Out': record.checkOut ? format(new Date(record.checkOut), 'pp') : 'Not marked',
      'Attendance %': record.attendancePercentage,
    };
  });
  
  const ws = XLSX.utils.json_to_sheet(exportData);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, 'Attendance');
  
  XLSX.writeFile(wb, 'attendance-report.xlsx');
};