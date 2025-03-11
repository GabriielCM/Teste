﻿from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class INC(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nf = db.Column(db.Integer, nullable=False, unique=False)
    data = db.Column(db.String(10), nullable=False)
    
    # Modificação: O representante agora é uma relação com a tabela User
    representante_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    representante = db.relationship('User', backref=db.backref('incs_representadas', lazy=True))
    
    # Manter o campo de texto para compatibilidade com dados existentes
    representante_nome = db.Column(db.String(100), nullable=True)
    
    fornecedor = db.Column(db.String(100), nullable=False)
    item = db.Column(db.String(20), nullable=False)
    quantidade_recebida = db.Column(db.Integer, nullable=False)
    quantidade_com_defeito = db.Column(db.Integer, nullable=False)
    descricao_defeito = db.Column(db.Text, default="")
    urgencia = db.Column(db.String(20), default="Moderada")
    acao_recomendada = db.Column(db.Text, default="")
    fotos = db.Column(db.Text, default="[]")
    status = db.Column(db.String(20), default="Em andamento")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    oc = db.Column(db.Integer, unique=True, nullable=False)

class LayoutSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    element = db.Column(db.String(20), unique=True, nullable=False)
    foreground = db.Column(db.String(7), default="#000000")
    background = db.Column(db.String(7), default="#ffffff")
    font_family = db.Column(db.String(50), default="Helvetica")
    font_size = db.Column(db.Integer, default=12)

class Fornecedor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    razao_social = db.Column(db.String(100), nullable=False)
    cnpj = db.Column(db.String(18), unique=True, nullable=False)
    fornecedor_logix = db.Column(db.String(100), nullable=False)

# Novo modelo para Rotina de Inspeção
class RotinaInspecao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    inspetor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Relaciona com o usuário
    data_inspecao = db.Column(db.DateTime, default=datetime.utcnow)
    registros = db.Column(db.Text, nullable=False)  # JSON com os registros (itens inspecionados/adiados)
    inspetor = db.relationship('User', backref=db.backref('rotinas', lazy=True))


class SolicitacaoFaturamento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    numero = db.Column(db.Integer, unique=True, nullable=False)
    tipo = db.Column(db.String(30), nullable=False)  # Conserto, Conserto em Garantia, Devolução
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    usuario = db.relationship('User', backref=db.backref('solicitacoes', lazy=True))
    fornecedor = db.Column(db.String(100), nullable=False)
    volumes = db.Column(db.Integer, nullable=False)
    tipo_frete = db.Column(db.String(3), nullable=False)  # CIF, FOB
    observacoes = db.Column(db.Text, nullable=True)
    
    # Relacionamento com as INCs - Usando uma tabela auxiliar para armazenar também a quantidade
    itens = db.relationship('ItemSolicitacaoFaturamento', backref='solicitacao', lazy=True, cascade="all, delete-orphan")

# Tabela de relacionamento entre SolicitacaoFaturamento e INC
class ItemSolicitacaoFaturamento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    solicitacao_id = db.Column(db.Integer, db.ForeignKey('solicitacao_faturamento.id'), nullable=False)
    inc_id = db.Column(db.Integer, db.ForeignKey('inc.id'), nullable=False)
    inc = db.relationship('INC')
    quantidade = db.Column(db.Integer, nullable=False)
    
class PrateleiraNaoConforme(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item = db.Column(db.String(20), nullable=False)
    descricao = db.Column(db.String(255), nullable=False)
    quantidade = db.Column(db.Float, nullable=False)
    data_ultima_movimentacao = db.Column(db.String(10), nullable=False)
    data_importacao = db.Column(db.DateTime, default=datetime.utcnow)
    tipo_defeito = db.Column(db.String(20), nullable=False, default="Produção")  # "Recebimento" ou "Produção"
    inc_id = db.Column(db.Integer, db.ForeignKey('inc.id'), nullable=True)
    inc = db.relationship('INC', backref=db.backref('itens_prateleira', lazy=True))
    
    @property
    def age_in_hours(self):
        """Retorna a idade dos dados em horas."""
        if self.data_importacao:
            delta = datetime.utcnow() - self.data_importacao
            return delta.total_seconds() / 3600
        return 0
    
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)  # Novo campo para email
    is_admin = db.Column(db.Boolean, default=False)
    is_representante = db.Column(db.Boolean, default=False)  # Novo campo para marcar se é representante
    permissions = db.Column(db.Text, default='{}')  # JSON para armazenar permissões
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Propriedades para gerenciar permissões
    def has_permission(self, permission_name):
        """Verifica se o usuário tem uma permissão específica"""
        if self.is_admin:  # Administradores têm todas as permissões
            return True
        
        try:
            perms = json.loads(self.permissions)
            return perms.get(permission_name, False)
        except:
            return False