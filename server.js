const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// 中间件
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// 数据库连接
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/baihuo-mall';

mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('MongoDB 连接成功'))
.catch(err => console.error('MongoDB 连接失败:', err));

// 用户模型
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    password: { type: String, required: true },
    avatar: { type: String, default: '' },
    addresses: [{
        name: String,
        phone: String,
        province: String,
        city: String,
        district: String,
        detail: String,
        isDefault: { type: Boolean, default: false }
    }],
    favorites: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// 商品模型
const productSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    price: { type: Number, required: true },
    originalPrice: { type: Number },
    category: { type: String, required: true },
    subcategory: { type: String },
    brand: { type: String },
    images: [String],
    stock: { type: Number, default: 0 },
    sales: { type: Number, default: 0 },
    rating: { type: Number, default: 0 },
    reviewCount: { type: Number, default: 0 },
    tags: [String],
    specifications: {
        type: Map,
        of: String
    },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Product = mongoose.model('Product', productSchema);

// 订单模型
const orderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    orderNumber: { type: String, required: true, unique: true },
    items: [{
        productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
        title: String,
        price: Number,
        quantity: Number,
        image: String
    }],
    totalAmount: { type: Number, required: true },
    discountAmount: { type: Number, default: 0 },
    finalAmount: { type: Number, required: true },
    shippingAddress: {
        name: String,
        phone: String,
        province: String,
        city: String,
        district: String,
        detail: String
    },
    paymentMethod: { type: String, required: true },
    paymentStatus: { 
        type: String, 
        enum: ['pending', 'paid', 'failed', 'refunded'], 
        default: 'pending' 
    },
    orderStatus: { 
        type: String, 
        enum: ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'], 
        default: 'pending' 
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Order = mongoose.model('Order', orderSchema);

// 评价模型
const reviewSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    orderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Order', required: true },
    rating: { type: Number, required: true, min: 1, max: 5 },
    content: { type: String, required: true },
    images: [String],
    isAnonymous: { type: Boolean, default: false },
    likes: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

const Review = mongoose.model('Review', reviewSchema);

// JWT 验证中间件
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: '访问令牌缺失' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'baihuo_secret_key', (err, user) => {
        if (err) {
            return res.status(403).json({ message: '访问令牌无效' });
        }
        req.user = user;
        next();
    });
};

// API 路由

// 用户注册
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, phone, password } = req.body;

        // 检查用户是否已存在
        const existingUser = await User.findOne({ 
            $or: [{ email }, { username }] 
        });
        
        if (existingUser) {
            return res.status(400).json({ message: '用户名或邮箱已存在' });
        }

        // 加密密码
        const hashedPassword = await bcrypt.hash(password, 10);

        // 创建新用户
        const user = new User({
            username,
            email,
            phone,
            password: hashedPassword
        });

        await user.save();

        // 生成 JWT
        const token = jwt.sign(
            { userId: user._id, username: user.username },
            process.env.JWT_SECRET || 'baihuo_secret_key',
            { expiresIn: '30d' }
        );

        res.status(201).json({
            message: '注册成功',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                phone: user.phone
            }
        });
    } catch (error) {
        console.error('注册错误:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 用户登录
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // 查找用户
        const user = await User.findOne({ 
            $or: [{ email }, { username: email }] 
        });
        
        if (!user) {
            return res.status(400).json({ message: '用户不存在' });
        }

        // 验证密码
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ message: '密码错误' });
        }

        // 生成 JWT
        const token = jwt.sign(
            { userId: user._id, username: user.username },
            process.env.JWT_SECRET || 'baihuo_secret_key',
            { expiresIn: '30d' }
        );

        res.json({
            message: '登录成功',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                phone: user.phone
            }
        });
    } catch (error) {
        console.error('登录错误:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 获取商品列表
app.get('/api/products', async (req, res) => {
    try {
        const { 
            page = 1, 
            limit = 8, 
            category, 
            search, 
            sort = 'createdAt',
            order = 'desc'
        } = req.query;

        const query = { isActive: true };
        
        if (category && category !== 'all') {
            query.category = category;
        }
        
        if (search) {
            query.$or = [
                { title: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } },
                { tags: { $in: [new RegExp(search, 'i')] } }
            ];
        }

        const sortOrder = order === 'desc' ? -1 : 1;
        const sortObj = { [sort]: sortOrder };

        const products = await Product.find(query)
            .sort(sortObj)
            .limit(limit * 1)
            .skip((page - 1) * limit)
            .exec();

        const total = await Product.countDocuments(query);

        res.json({
            products,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total
        });
    } catch (error) {
        console.error('获取商品列表错误:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 获取商品详情
app.get('/api/products/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        
        if (!product) {
            return res.status(404).json({ message: '商品不存在' });
        }

        res.json(product);
    } catch (error) {
        console.error('获取商品详情错误:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 创建订单
app.post('/api/orders', authenticateToken, async (req, res) => {
    try {
        const { items, shippingAddress, paymentMethod } = req.body;
        const userId = req.user.userId;

        // 验证商品库存
        for (const item of items) {
            const product = await Product.findById(item.productId);
            if (!product) {
                return res.status(400).json({ message: `商品 ${item.title} 不存在` });
            }
            if (product.stock < item.quantity) {
                return res.status(400).json({ message: `商品 ${item.title} 库存不足` });
            }
        }

        // 计算总金额
        let totalAmount = 0;
        const orderItems = [];
        
        for (const item of items) {
            const product = await Product.findById(item.productId);
            const itemTotal = product.price * item.quantity;
            totalAmount += itemTotal;
            
            orderItems.push({
                productId: product._id,
                title: product.title,
                price: product.price,
                quantity: item.quantity,
                image: product.images[0] || ''
            });
        }

        // 生成订单号
        const orderNumber = 'BH' + Date.now() + Math.random().toString(36).substr(2, 4).toUpperCase();

        // 创建订单
        const order = new Order({
            userId,
            orderNumber,
            items: orderItems,
            totalAmount,
            finalAmount: totalAmount,
            shippingAddress,
            paymentMethod
        });

        await order.save();

        // 更新商品库存和销量
        for (const item of items) {
            await Product.findByIdAndUpdate(item.productId, {
                $inc: { 
                    stock: -item.quantity,
                    sales: item.quantity
                }
            });
        }

        res.status(201).json({
            message: '订单创建成功',
            order: {
                id: order._id,
                orderNumber: order.orderNumber,
                totalAmount: order.totalAmount,
                finalAmount: order.finalAmount,
                paymentStatus: order.paymentStatus,
                orderStatus: order.orderStatus
            }
        });
    } catch (error) {
        console.error('创建订单错误:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 获取用户订单列表
app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const userId = req.user.userId;

        const orders = await Order.find({ userId })
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit)
            .populate('items.productId', 'title images')
            .exec();

        const total = await Order.countDocuments({ userId });

        res.json({
            orders,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total
        });
    } catch (error) {
        console.error('获取订单列表错误:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 获取商品评价
app.get('/api/products/:id/reviews', async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const productId = req.params.id;

        const reviews = await Review.find({ productId })
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit)
            .populate('userId', 'username avatar')
            .exec();

        const total = await Review.countDocuments({ productId });
        
        // 计算平均评分
        const ratingStats = await Review.aggregate([
            { $match: { productId: mongoose.Types.ObjectId(productId) } },
            {
                $group: {
                    _id: null,
                    averageRating: { $avg: '$rating' },
                    totalReviews: { $sum: 1 },
                    ratingDistribution: {
                        $push: '$rating'
                    }
                }
            }
        ]);

        res.json({
            reviews,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total,
            stats: ratingStats[0] || { averageRating: 0, totalReviews: 0 }
        });
    } catch (error) {
        console.error('获取商品评价错误:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 添加商品评价
app.post('/api/reviews', authenticateToken, async (req, res) => {
    try {
        const { productId, orderId, rating, content, images = [] } = req.body;
        const userId = req.user.userId;

        // 验证用户是否购买过该商品
        const order = await Order.findOne({
            _id: orderId,
            userId,
            'items.productId': productId,
            orderStatus: 'delivered'
        });

        if (!order) {
            return res.status(400).json({ message: '只能评价已购买的商品' });
        }

        // 检查是否已经评价过
        const existingReview = await Review.findOne({ userId, productId, orderId });
        if (existingReview) {
            return res.status(400).json({ message: '您已经评价过该商品' });
        }

        // 创建评价
        const review = new Review({
            userId,
            productId,
            orderId,
            rating,
            content,
            images
        });

        await review.save();

        // 更新商品评分
        const reviews = await Review.find({ productId });
        const averageRating = reviews.reduce((sum, r) => sum + r.rating, 0) / reviews.length;
        
        await Product.findByIdAndUpdate(productId, {
            rating: averageRating,
            reviewCount: reviews.length
        });

        res.status(201).json({
            message: '评价添加成功',
            review
        });
    } catch (error) {
        console.error('添加评价错误:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 获取用户信息
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) {
            return res.status(404).json({ message: '用户不存在' });
        }
        res.json(user);
    } catch (error) {
        console.error('获取用户信息错误:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 更新用户信息
app.put('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const { username, phone, avatar } = req.body;
        const userId = req.user.userId;

        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { username, phone, avatar, updatedAt: Date.now() },
            { new: true }
        ).select('-password');

        res.json({
            message: '用户信息更新成功',
            user: updatedUser
        });
    } catch (error) {
        console.error('更新用户信息错误:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 管理收货地址
app.post('/api/user/addresses', authenticateToken, async (req, res) => {
    try {
        const address = req.body;
        const userId = req.user.userId;

        const user = await User.findById(userId);
        
        // 如果设置为默认地址，先取消其他默认地址
        if (address.isDefault) {
            user.addresses.forEach(addr => addr.isDefault = false);
        }
        
        user.addresses.push(address);
        await user.save();

        res.status(201).json({
            message: '地址添加成功',
            addresses: user.addresses
        });
    } catch (error) {
        console.error('添加地址错误:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 静态文件服务
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 错误处理中间件
app.use((err, req, res, next) => {
    console.error('服务器错误:', err);
    res.status(500).json({ message: '服务器内部错误' });
});

// 启动服务器
app.listen(PORT, () => {
    console.log(`百货网站服务器运行在端口 ${PORT}`);
    console.log(`访问地址: http://localhost:${PORT}`);
});

/*来源：元宝，提示词：百货网站后端服务器代码，范围：server.js 全文*/