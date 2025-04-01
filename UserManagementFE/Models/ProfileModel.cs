namespace UserManagementFE.Models
{
    public class ProfileModel
    {
        public int Id { get; set; }
        public string Password { get; set; } = string.Empty;
        public string? Username { get; set; }
        public string? HoTen { get; set; }
        public DateTime NgaySinh { get; set; } // DateTime không cần required vì là value type
        public string? GioiTinh { get; set; }
        public string? SoCCCD { get; set; }
        public string? Sdt { get; set; }
        public string? Email { get; set; }
        public string? DiaChiThuongTru { get; set; }
        public string? DiaChiTamTru { get; set; }
        public string? NgheNghiep { get; set; }
        public string? HonNhan { get; set; }
        public string? BangLaiXe { get; set; }
        public string? SoTKNganHang { get; set; }
        public string? Role { get; set; }
    }
}
