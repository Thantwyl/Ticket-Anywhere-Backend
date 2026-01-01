from rest_framework.permissions import BasePermission

class IsAdminOrReadOnly(BasePermission):
    """
    Custom permission for public endpoints (Banner, Category, Event):
    - Anyone can read (GET) - no authentication required
    - Only admin can create/update/delete (POST/PUT/PATCH/DELETE)
    """
    def has_permission(self, request, view):
        if request.method in ['GET']: # Read-only methods for eveyone (even unauthenticated)
            return True        
        return request.user.is_authenticated and request.user.is_staff # only admin can perform write operations

class TicketPermission(BasePermission):
    """
    Custom permission for ticket operations:
    - Registered customers can create and view their own tickets (limited fields)
    - Only admin can update/delete and access all fields
    """
    
    def has_permission(self, request, view):
        """ Check if user has permission to access the endpoint """
        if not request.user.is_authenticated: # must be authenticated for any ticket operation
            return False
        if request.method in ['GET', 'POST']: # allow GET and POST for authenticated users
            return True
        if request.method in ['PUT', 'PATCH', 'DELETE']: # only admin can modify tickets UPDATE/DELETE
            return request.user.is_staff          
        return False
    
    def has_object_permission(self, request, view, obj):
        """ Check permissions for specific ticket object """
        if request.method == 'GET': # user can view their own tickets
            if obj.order and obj.order.customer == request.user:
                return True
            return request.user.is_staff # admin can view all tickets
        if request.method in ['PUT', 'PATCH', 'DELETE']: # only admin can modify tickets
            return request.user.is_staff 
            
        return False

class OrderPermission(BasePermission):
    """
    Custom permission for orders (bridging table):
    - Orders are auto-generated, mainly for admin management
    - Customers can view their own orders
    - Only admin can modify orders
    """
    
    def has_permission(self, request, view):
        """ Check if user has permission to access orders """
        if not request.user.is_authenticated: # must be authenticated for any order operation
            return False
        if request.method == 'GET': # allow GET for authenticated users, full access for admin
            return True
        else:
            return request.user.is_staff
    
    def has_object_permission(self, request, view, obj):
        """ Check permissions for specific order object """
        if request.method == 'GET': # allow users to view their own orders
            return obj.customer == request.user or request.user.is_staff
        return request.user.is_staff # only admin can modify orders