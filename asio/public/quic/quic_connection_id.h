#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <stdexcept>

namespace quic
{


	class connection_id
	{
	public:
		using value_type = unsigned char;
		using size_type = std::uint_fast8_t;
		using difference_type = std::ptrdiff_t;
		using reference = value_type&;
		using const_reference = const value_type&;
		using pointer = value_type*;
		using const_pointer = const value_type*;
		using iterator = pointer;
		using const_iterator = const_pointer;
		using reverse_iterator = std::reverse_iterator<iterator>;
		using const_reverse_iterator = std::reverse_iterator<const_iterator>;


		constexpr connection_id() noexcept
			: data_{}, size_(0)
		{
		}

		template<size_t Size>
		constexpr connection_id(const value_type (& data)[Size]) noexcept
			: data_{}, size_(Size)
		{
			static_assert(Size <= max_size_);
			for (size_type i = 0; i < Size; i++)
			{
				data_[i] = data[i];
			}
		}

		template<size_t Size>
		constexpr connection_id(const std::array<value_type, Size>& data) noexcept
			: data_{}, size_(Size)
		{
			static_assert(Size <= max_size_);
			for (size_type i = 0; i < Size; i++)
			{
				data_[i] = data[i];
			}
		}

		constexpr connection_id(const_pointer data, size_type size)
			: data_{}, size_(size)
		{
			if (size > max_size_)
			{
				throw std::length_error("maximum connection id length (20) exceeded");
			}
			for (size_type i = 0; i < size; i++)
			{
				data_[i] = data[i];
			}
		}

		constexpr connection_id(const connection_id&) noexcept = default;
		constexpr connection_id& operator=(const connection_id&) noexcept = default;

		constexpr bool empty() const noexcept
		{
			return size_ == 0;
		}

		constexpr size_type size() const
		{
			return size_;
		}
		constexpr static size_type max_size()
		{
			return max_size_;
		}

		constexpr void resize(size_type size)
		{
			if (size > max_size_)
			{
				throw std::length_error("maximum connection id length (20) exceeded");
			}
			size_ = size;
		}

		constexpr reference at(size_type p)
		{
			if (p >= size())
			{
				throw std::out_of_range("array index out of range");
			}
			return data_[p];
		}
		constexpr const_reference at(size_type p) const
		{
			if (p >= size())
			{
				throw std::out_of_range("array index out of range");
			}
			return data_[p];
		}

		constexpr reference operator[](size_type p)
		{
			return data_[p];
		}
		constexpr const_reference operator[](size_type p) const
		{
			return data_[p];
		}

		constexpr reference front()
		{
			return data_.front();
		}
		constexpr const_reference front() const
		{
			return data_.front();
		}

		constexpr reference back()
		{
			return *std::prev(end());
		}
		constexpr const_reference back() const
		{
			return *std::prev(end());
		}

		constexpr pointer data()
		{
			return data_.data();
		}
		constexpr const_pointer data() const
		{
			return data_.data();
		}

		constexpr iterator begin()
		{
			return data_.begin();
		}
		constexpr const_iterator begin() const
		{
			return data_.begin();
		}

		constexpr const_iterator cbegin() const
		{
			return data_.cbegin();
		}

		constexpr iterator end()
		{
			return std::next(begin(), size_);
		}
		constexpr const_iterator end() const
		{
			return std::next(begin(), size_);
		}

		constexpr const_iterator cend() const
		{
			return std::next(begin(), size_);
		}

		constexpr reverse_iterator rbegin()
		{
			return std::next(data_.rbegin(), max_size_ - size_);
		}
		constexpr const_reverse_iterator rbegin() const
		{
			return std::next(data_.rbegin(), max_size_ - size_);
		}
		constexpr const_reverse_iterator crbegin() const
		{
			return std::next(data_.rbegin(), max_size_ - size_);
		}

		constexpr reverse_iterator rend()
		{
			return data_.rend();
		}
		constexpr const_reverse_iterator rend() const
		{
			return data_.rend();
		}

		constexpr const_reverse_iterator crend() const
		{
			return data_.crend();
		}

	private:
		static constexpr size_type max_size_ = 20;
		using array_type = std::array<value_type, max_size_>;
		array_type data_;
		size_type size_;
	};

	inline bool operator==(const connection_id& l, const connection_id& r) noexcept
	{
		return l.size() == r.size() && std::equal(l.begin(), l.end(), r.begin());
	}

	inline bool operator!=(const connection_id& l, const connection_id& r) noexcept
	{
		return l.size() != r.size() || !std::equal(l.begin(), l.end(), r.begin());
	}

	inline bool operator<(const connection_id& l, const connection_id& r) noexcept
	{
		return std::lexicographical_compare(l.begin(), l.end(), r.begin(), r.end());
	}

	inline bool operator>(const connection_id& l, const connection_id& r) noexcept
	{
		return std::lexicographical_compare(r.begin(), r.end(), l.begin(), l.end());
	}

	inline bool operator<=(const connection_id& l, const connection_id& r) noexcept
	{
		return !(l > r);
	}

	inline bool operator>=(const connection_id& l, const connection_id& r) noexcept
	{
		return !(l < r);
	}

	inline void swap(connection_id& lhs, connection_id& rhs) noexcept
	{
		auto tmp = lhs;
		lhs = std::move(rhs);
		rhs = std::move(tmp);
	}

} // namespace quic
