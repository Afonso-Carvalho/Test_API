from django.contrib.auth.models import User
from rest_framework.test import APITestCase
from django.contrib.auth import authenticate
from django.urls import reverse
from rest_framework import status

class AuthenticationUserTestCase(APITestCase):

    def setUp(self):
        self.list_url = reverse('programas-list')# reverse pega as lista de urls dadas para o models programa
        self.user = User.objects.create_user('c3po', password='123456')

    def test_autenticao_user_com_credenciais_corretas(self):
        """Teste que verifica a autenticação de um user com as credenciais corretas"""
        user = authenticate(username = 'c3po',password='123456')
        self.assertTrue((user is not None) and user.is_authenticated)

    def test_requisicao_nao_autorizada(self):
        """Teste que verifica uma requisição get não autorizada"""
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code,status.HTTP_401_UNAUTHORIZED)

    def test_autenticacao_de_user_incorreto(self):
        """Verificando resposta caso o username na autenticação esteja incorreto"""
        user = authenticate(username = 'c3pp',password='123456')
        self.assertFalse((user is not None) and user.is_authenticated)

    def test_autenticacao_de_password_incorreto(self):
        """Verificando resposta caso a senha na autenticação esteja incorreto"""
        user = authenticate(username = 'c3pp',password='123356')
        self.assertFalse((user is not None) and user.is_authenticated)

    def test_requisicao_get_com_user_autenticado(self):
        """Teste para verificar uma requisição get de um user autenticado"""
        self.client.force_authenticate(self.user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        