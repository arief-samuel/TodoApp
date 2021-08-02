using System.ComponentModel.DataAnnotations;

namespace TodoApp.Dtos.Requests
{
    public class TokenRequest
    {
        [Required]
        public string Token { get; set; }

        [Required]
        public string RefreshToken { get; set; }
    }
}