<?php 
namespace App\Models;
use CodeIgniter\Model;
class CrudModel extends Model
{
    protected $table = 'crud_tbl';
    protected $primaryKey = 'id';
    
    protected $allowedFields = ['name', 'email'];
    
    public function __construct()
    {
        parent::__construct();
        $this->db = db_connect();
    }
    
    public function insertdatafun($data)
    {
        return $this->db->table('crud_tbl')->insert($data);
    }
    
    public function emailExist($email) {
        $data['count'] = $this->db->table($this->table)->where(['email' => $email])->countAllResults();
        return $data['count'];
    }
    
    public function viewdatafun()
    {
        $query = $this->db->query('SELECT * FROM ' . $this->table . ' order by id DESC');
        return $query->getResultArray();
    }
    
    public function joindatafun(){
        $builder = $this->db->table('crud_tbl');
        $builder    = $builder->select('crud_tbl.*,joinsample_tbl.msg ,joinsample_tbl.crud_tbl_id');
        $builder    = $builder->join('joinsample_tbl', 'joinsample_tbl.crud_tbl_id = crud_tbl.id');
        return $query  = $builder->get()->getResultArray();
    }
    
    public function getuserdata($userId) {
        $query = $this->db->query("select * from {$this->table} where id='$userId'");
        return $query->getRowArray();
    }

}