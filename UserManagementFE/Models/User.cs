namespace UserManagementFE.Models
{
    public class User
    {
        public required string Username { get; set; }
        public required string Password { get; set; }
        public required string HoTen { get; set; }
        public DateTime NgaySinh { get; set; } // DateTime không cần required vì là value type
        public required string GioiTinh { get; set; }
        public required string SoCCCD { get; set; }
        public required string Sdt { get; set; }
        public string? Email { get; set; }
        public required string DiaChiThuongTru { get; set; }
        public string? DiaChiTamTru { get; set; }
        public string? NgheNghiep { get; set; }
        public string? HonNhan { get; set; }
        public string? BangLaiXe { get; set; }
        public string? SoTkNganHang { get; set; }
    }
}